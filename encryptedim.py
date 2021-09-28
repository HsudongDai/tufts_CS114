from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

import argparse
import select
import signal
import socket
import sys

BLOCK_SIZE = AES.block_size
# 不足BLOCK_SIZE的补位(s可能是含中文，而中文字符utf-8编码占3个位置,gbk是2，所以需要以len(s.encode())，而不是len(s)计算补码)
pad = lambda s: s + (BLOCK_SIZE - len(s.encode()) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s.encode()) % BLOCK_SIZE)
# 去除补位
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class SelectServer:
    def __init__(self, confkey, authkey):
        self.host = 'localhost'
        self.port = 9999

        self.confkey = confkey.encode('utf-8')
        self.authkey = authkey.encode('utf-8')

        # signal.signal(signal, self.handler)
        # no need for it.
        # when meeting Ctrl+C, select would terminate by itself
        # when meeting Ctrl+D, self.run() would raise an exception then invoke sys.exit()

        # AF_INET means using IPv4
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(3)  # listen up to 3 connections. in this case, 1 is enough
        # print('listening on 127.0.0.1:9999')

        self.in_channels = [self.socket, sys.stdin]  # list of readable sockets for select
        self.out_channels = []  # list of writable sockets for select

        # self.msg_queues = {}                      # one-to-one connection, unnecessary to use a dict for msg queue
        self.encryptor = AES.new(self.confkey, AES.MODE_CBC)
        self.decryptor = AES.new(self.confkey, AES.MODE_CBC)
        # self.verifier = HMAC.new(self.authkey, digestmod=SHA256)

    def run(self):
        while self.in_channels:
            readable, _, _ = select.select(self.in_channels, [], [])

            for r in readable:
                # r is the server, so build new connection with the client
                if r is self.socket:
                    cli_conn, cli_addr = self.socket.accept()
                    self.in_channels.append(cli_conn)
                    # print(f'Connection to {cli_addr} Established')

                # r is sys.stdin, read inputs and send to the client
                elif r is sys.stdin:
                    msg = sys.stdin.readline()
                    # though sys.stdin.readline() won't stop until reading an EOF or \n,
                    # it would be a better idea to check every message

                    # when meeting Ctrl+D, it would raise an IndexError
                    # so call sys.exit to kill the process
                    if msg[-1] != '\n':
                        try:
                            msg += '\n'
                        except IndexError:
                            sys.exit(-1)
                    # sendall forces to send all messages in the buffer
                    # all messages must be encoded in UTF-8
                    # print("MSG:", msg)
                    enc_msg = self.encryptor.encrypt(pad(msg).encode('utf-8'))

                    # hash = self.verifier.update(enc_msg).digest()
                    # enc_msg = enc_msg + hash
                    # print("ENC_MSG", enc_msg)
                    self.in_channels[-1].sendall(enc_msg)
                # the connection to the client which has been built,
                else:
                    data = r.recv(1024)
                    # data is not none, that is connection has not been broken
                    if data:
                        # print(f"Receive message from {r.getpeername()}")
                        # force to flush every message by setting flush=True
                        # data, hash = data[:-32], data[-32]
                        # try:
                        #     self.verifier.update(data).verify(hash)
                        # except ValueError:
                        #     sys.exit(-2)
                        data = self.decryptor.decrypt(data)
                        # print(self.verifier.update(data).hexdigest())

                        data = unpad(data).decode('utf-8')
                        data = data.strip('\n')
                        data += '\n'
                        sys.stdout.write(data)
                        sys.stdout.flush()
                        # print(data, flush=True)

                        if r not in self.out_channels:
                            self.out_channels.append(r)
                    # connection has been broken, sockets must be removed from lists then closed
                    else:
                        # print(f"Connection to {r.getpeername()} has been closed")
                        if r in self.out_channels:
                            self.out_channels.remove(r)
                        self.in_channels.remove(r)
                        r.close()
            # Wait 0.5 second
            # sleep(0.5)


class SelectClient:
    def __init__(self, host, confkey, authkey):
        self.dst_host = host
        self.dst_port = 9999
        self.confkey = confkey.encode('utf-8')
        self.authkey = authkey.encode('utf-8')

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.socket.setblocking(False)
        self.socket.connect((self.dst_host, self.dst_port))

        self.in_channels = [self.socket, sys.stdin]
        self.encryptor = AES.new(self.confkey, AES.MODE_CBC)
        self.decryptor = AES.new(self.confkey, AES.MODE_CBC)
        self.verifier = HMAC.new(self.authkey, digestmod=SHA256)
        # self.out_channels = []

    def run(self):
        while True:
            readable, _, _ = select.select(self.in_channels, [], [])
            for r in readable:
                # if r is the socket, then receive the message and print
                if r is self.socket:
                    msg = r.recv(1024)
                    if not msg:
                        sys.exit(-1)
                    else:
                        # sys.stdout.write(msg.decode('utf-8'))
                        # msg, hashx = msg[:-32], msg[-32:]
                        # try:
                        #     self.verifier.update(msg).verify(hashx)
                        # except ValueError:
                        #     sys.exit(-2)
                        msg = self.decryptor.decrypt(msg)
                        msg = unpad(msg).decode('utf-8')
                        msg = msg.strip('\n')
                        msg += '\n'
                        sys.stdout.write(msg)
                        sys.stdout.flush()
                        # print(msg, flush=True)

                # else means r is the sys.stdin, so read the line then send the message
                else:
                    msg = r.readline()
                    if msg[-1] != '\n':
                        try:
                            msg += '\n'
                        except IndexError:
                            sys.exit(-1)
                    msg = self.encryptor.encrypt(pad(msg).encode('utf-8'))
                    # hashx = self.verifier.update(msg).digest()
                    # msg += hashx

                    self.socket.sendall(msg)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--s", required=False, action="count",
                        help="If True, then listener; If False, then connector")
    parser.add_argument("--c", type=str, default="localhost", help="The ip address of the listener", required=False)
    parser.add_argument("--confkey", required=True, type=str, help="Confidential Key")
    parser.add_argument("--authkey", required=True, type=str, help="Authentication Key")
    args = parser.parse_args()

    # The key must be 32 bytes long to use AES-256
    assert len(args.confkey.encode('utf-8'))== 32
    # if args.s is False and args.c is not None:
    #     raise AttributeError("s and c cannot be set simultaneously")

    if args.s and args.s >= 1:
        SelectServer(args.confkey, args.authkey).run()
    elif args.c:
        SelectClient(args.c, args.confkey, args.authkey).run()
    else:
        pass
