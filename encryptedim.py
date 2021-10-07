from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

import argparse
import select
import socket
import sys

BLOCK_SIZE = AES.block_size


def pad(s: str) -> str:
    padding = (BLOCK_SIZE - len(s.encode("utf-8")) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s.encode("utf-8")) % BLOCK_SIZE)
    return s + padding


def unpad(s: str) -> str:
    return s[:-ord(s[len(s) - 1:])]


class SelectServer:
    def __init__(self, confkey, authkey, iv):
        self.host = 'localhost'
        self.port = 9999

        self.confkey = confkey.encode('utf-8')
        self.authkey = authkey.encode('utf-8')

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        # self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.socket.bind((self.host, self.port))
        self.socket.listen(3)  # listen up to 3 connections. in this case, 1 is enough
        # print('listening on 127.0.0.1:9999')

        self.in_channels = [self.socket, sys.stdin]  # list of readable sockets for select
        self.out_channels = []  # list of writable sockets for select

        self.encryptor = AES.new(self.confkey, AES.MODE_CBC, iv)
        self.decryptor = AES.new(self.confkey, AES.MODE_CBC, iv)
        self.verifier = HMAC.new(self.authkey, digestmod=SHA256)

    def wait_for_connection(self) -> socket.socket:
        conn, _ = self.socket.accept()
        self.in_channels.append(conn)
        return conn

    def encrypt(self, msg: str) -> bytes:
        padded_msg = pad(msg)
        # print('Padded msg:', padded_msg.encode('utf-8'))
        enc_msg = self.encryptor.encrypt(padded_msg.encode("utf-8"))
        # print('Encrypted msg: ', enc_msg)
        return enc_msg

    def decrypt(self, enc_msg: bytes) -> str:
        # print("enc_msg is: ", enc_msg)
        temp = self.decryptor.decrypt(enc_msg)
        # print("decrypted msg is: ", temp)
        enc_msg = unpad(temp.decode("utf-8"))
        # print("unpadded msg: ", enc_msg)
        return enc_msg

    def generate_mac(self, data: bytes) -> bytes:
        return self.verifier.update(data).digest()

    def verify_mac(self, data: bytes, mac: bytes) -> None:
        self.verifier.update(data).verify(mac)
            # sys.exit(-1)

    def run(self):
        sock = self.wait_for_connection()
        while self.in_channels:
            readable, _, _ = select.select(self.in_channels, [], [])

            if sock in readable:
                raw_data = sock.recv(1500)
                data, mac = raw_data[:-32], raw_data[-32:]
                # print("Received data: ", data)
                try:
                    self.verify_mac(data, mac)
                except ValueError:
                    print("HMAC verification failed")
                    if sock in self.out_channels:
                        self.out_channels.remove(sock)
                    self.in_channels.remove(sock)
                    sock.close()
                data = self.decrypt(data)
                if data == '':
                    if sock in self.out_channels:
                        self.out_channels.remove(sock)
                    self.in_channels.remove(sock)
                    sock.close()
                    break
                sys.stdout.write(data)
                sys.stdout.flush()
            # r is sys.stdin, read inputs and send to the client
            if sys.stdin in readable:
                msg = sys.stdin.readline()
                # print("Server read message: ", msg)
                if msg is None or msg == "":
                    break
                msg = self.encrypt(msg)
                mac = self.generate_mac(msg)
                msg += mac
                sock.sendall(msg)


class SelectClient:
    """
    The client side of instant messaging service.
    """
    def __init__(self, host: str, confkey: str, authkey: str, iv: str):
        """
        :param host: the address of server
        :param confkey: the confidential key of AES256
        :param authkey: the authentification key of SHA256 in HMAC
        :param iv: initialization vector to initialize encryptor in CBC mode. Without it, the first message would be lost
        since it is viewed as the iv.
        """
        self.dst_host = host
        self.dst_port = 9999
        self.confkey = confkey.encode('utf-8')
        self.authkey = authkey.encode('utf-8')

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.socket.setblocking(False)
        self.socket.connect((self.dst_host, self.dst_port))

        self.in_channels = [self.socket, sys.stdin]
        self.encryptor = AES.new(self.confkey, AES.MODE_CBC, iv)
        self.decryptor = AES.new(self.confkey, AES.MODE_CBC, iv)
        self.verifier = HMAC.new(self.authkey, digestmod=SHA256)
        # self.out_channels = []

    def encrypt(self, msg: str) -> bytes:
        """
        Encrypt messages in bytes and return the encrypted bytes
        :param msg: str, plaintext you want to send.
        :return: enc_msg: str, ciphertext after encryption.
        """
        padded_msg = pad(msg)
        # print('Padded msg:', padded_msg.encode('utf-8'))
        enc_msg = self.encryptor.encrypt(padded_msg.encode("utf-8"))
        # print('Encrypted msg: ', enc_msg)
        return enc_msg

    def decrypt(self, enc_msg: bytes) -> str:
        """
        Decrypt the received ciphered message.
        :param enc_msg: bytes, ciphertext of raw messages
        :return: plain_msg: str, plaintext after decryption
        """
        # print("enc_msg is: ", enc_msg)
        temp = self.decryptor.decrypt(enc_msg)
        # print("decrypted msg is: ", temp)
        plain_msg = unpad(temp.decode("utf-8"))
        # print("unpadded msg: ", enc_msg)
        return plain_msg

    def generate_mac(self, data: bytes) -> bytes:
        return self.verifier.update(data).digest()

    def verify_mac(self, data: bytes, mac: bytes) -> None:
        try:
            self.verifier.update(data).verify(mac)
        except ValueError:
            print('ERROR: HMAC verification failed')
            sys.exit(-1)

    def run(self):
        while True:
            readable, _, _ = select.select(self.in_channels, [], [])
            for r in readable:
                # if r is the socket, then receive the message and print
                if r is self.socket:
                    msg = r.recv(1500)
                    # print("RAW_MSG: ", msg)
                    if not msg:
                        sys.exit(-1)
                    else:
                        msg, mac = msg[:-32], msg[-32:]
                        self.verify_mac(msg, mac)
                        msg = self.decrypt(msg)
                        sys.stdout.write(msg)
                        sys.stdout.flush()
                        # print(msg, flush=True)

                # else means r is the sys.stdin, so read the line then send the message
                else:
                    msg = r.readline()
                    # print("Client read message: ", msg)
                    msg = self.encrypt(msg)
                    # hashx = self.verifier.update(msg).digest()
                    # msg += hashx
                    mac = self.generate_mac(msg)
                    msg += mac
                    self.socket.sendall(msg)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--s", required=False, action="count",
                        help="If True, then listener; If False, then connector")
    parser.add_argument("--c", type=str, default="localhost", help="The ip address of the listener", required=False)
    parser.add_argument("--confkey", required=False, type=str, default='0' * 32, help="Confidential Key")
    parser.add_argument("--authkey", required=False, type=str, default='1' * 16, help="Authentication Key")
    args = parser.parse_args()

    # The key must be 32 bytes long to use AES-256
    # assert len(args.confkey.encode('utf-8')) == 32
    # if args.s is False and args.c is not None:
    #     raise AttributeError("s and c cannot be set simultaneously")
    # args.s = 1

    # length of iv must be strictly 16 bytes
    # to be more random, we pick the first 16 bytes from the confkey
    iv = args.confkey.encode('utf-8')[:16]

    if args.s and args.s >= 1:
        SelectServer(args.confkey, args.authkey, iv).run()
    elif args.c:
        SelectClient(args.c, args.confkey, args.authkey, iv).run()
    else:
        pass
