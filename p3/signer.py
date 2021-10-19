import argparse
import binascii
import select
import socket
import sys

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def mypad(somenum):
    return '0' * (4-len(str(somenum))) + str(somenum)


class GenKey(object):
    def __init__(self):
        self.pubkey_path = './mypubkey.pem'
        self.privkey_path = './myprivkey'

    def genkey(self):
        key_pair = RSA.generate(4096)
        pubkey = key_pair.publickey().export_key()
        privkey = key_pair.export_key()

        with open(self.pubkey_path, 'w') as f:
            f.write(pubkey.decode())

        with open(self.privkey_path, 'w') as f:
            f.write(privkey.decode())


class SelectClient:
    def __init__(self, host, message):
        self.dst_host = host
        self.dst_port = 9998  # note, it is not 9999

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.socket.setblocking(False)
        self.socket.connect((self.dst_host, self.dst_port))

        self.in_channels = [self.socket, sys.stdin]
        # self.out_channels = []
        self.privkey_path = './myprivkey'
        self.message = message

    def run(self):
        # self.message # 1st part
        pad_msg_len = mypad(len(self.message))          # 2nd part

        self.socket.send(pad_msg_len.encode(), socket.MSG_DONTROUTE)      # send 1st part
        self.socket.sendall(self.message.encode(), socket.MSG_DONTROUTE)  # send 2nd part

        digest = SHA256.new(self.message.encode())
        with open(self.privkey_path, 'r') as f:
            private_key = f.readlines()
        private_key = ''.join(private_key)
        private_key = RSA.import_key(private_key)

        signer = pkcs1_15.new(private_key)
        signature = signer.sign(digest)

        hex_signature = binascii.hexlify(signature)    # 4th part
        hex_signature_len = mypad(len(hex_signature))  # 3rd part

        self.socket.sendall(hex_signature_len.encode(), socket.MSG_DONTROUTE)  # send 3rd part
        self.socket.sendall(hex_signature, socket.MSG_DONTROUTE)               # send 4th part

        sys.exit(0)


class SelectServer:
    def __init__(self):
        self.host = 'localhost'
        self.port = 9998

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

    def wait_for_connection(self):
        conn, _ = self.socket.accept()
        self.in_channels.append(conn)
        # print('New connection!')
        return conn

    def run(self):
        while True:
            sock = self.wait_for_connection()
            while self.in_channels:
                readable, _, _ = select.select(self.in_channels, [], [])

                if sock in readable:
                    data = sock.recv(4, socket.MSG_WAITALL)
                    # data is not none, that is connection has not been broken
                    if data:
                        msg_len: str = data.decode()
                        i_msg_len: int = int(msg_len)
                        msg: str = sock.recv(i_msg_len, socket.MSG_WAITALL).decode()
                        sig_len: str = sock.recv(4, socket.MSG_WAITALL).decode()
                        i_sig_len: int = int(sig_len)
                        sig: str = sock.recv(i_sig_len, socket.MSG_WAITALL).decode()

                        sys.stdout.write(msg_len + msg + sig_len + sig)
                        sys.stdout.flush()

                        self.in_channels.remove(sock)
                        sock.close()

                        break
                # r is sys.stdin, read inputs and send to the client
                if sys.stdin in readable:
                    msg = sys.stdin.readline()
                    if msg is None or msg == "":
                        break
                    sock.sendall(msg.encode('utf-8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--genkey', action='store_true', required=False, help='if exists, generate RSA key and save')
    parser.add_argument('--c', dest='hostname', type=str, required=False, default='localhost', help='name of dst host')
    parser.add_argument('--m', dest='message', type=str, required=False, default='Hello World',
                        help='the message you want to send')
    # parser.add_argument("--s", dest='server_mode', required=False, action="store_true",
    #                     help="If True, then listener; If False, then connector")
    args = parser.parse_args()

    if args.genkey:
        GenKey().genkey()
    # elif args.server_mode:
    #     SelectServer().run()
    elif args.hostname:
        SelectClient(args.hostname, args.message).run()


