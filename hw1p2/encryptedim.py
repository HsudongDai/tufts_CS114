import os
import signal

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

import argparse
import select
import socket
import sys

BLOCK_SIZE = AES.block_size


def pad(s: str) -> str:
    padding = (BLOCK_SIZE - len(s.encode()) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s.encode()) % BLOCK_SIZE)
    return s + padding


def unpad(s: str) -> str:
    if len(s) == 0:
        return ""
    return s[:-ord(s[len(s) - 1:])]


class GeneralModule:
    def __init__(self, confkey, authkey):
        self.host = 'localhost'
        self.port = 9999

        self.confkey = confkey.encode()
        self.authkey = authkey.encode()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.in_channels = [self.socket, sys.stdin]  # list of readable sockets for select
        self.out_channels = []  # list of writable sockets for select

        self.encryptor = None
        self.decryptor = None
        # mac1 verifies iv+msg_len
        self.mac1_verifier = HMAC.new(self.authkey, digestmod=SHA256)
        # mac1 verifies msg
        self.mac2_verifier = HMAC.new(self.authkey, digestmod=SHA256)

        self.iv = None

    def encrypt(self, msg: str) -> bytes:
        padded_msg = pad(msg)
        enc_msg = self.encryptor.encrypt(padded_msg.encode())
        return enc_msg

    def decrypt(self, enc_msg: bytes) -> str:
        temp = self.decryptor.decrypt(enc_msg)
        enc_msg = unpad(temp.decode())
        return enc_msg

    def generate_mac1(self, data: bytes) -> bytes:
        return self.mac1_verifier.update(data).digest()

    def verify_mac1(self, data: bytes, mac: bytes) -> None:
        # print('mac1 in method: ', data)
        try:
            self.mac1_verifier.update(data).verify(mac)
        except ValueError:
            raise ValueError

    def generate_mac2(self, data: bytes) -> bytes:
        return self.mac2_verifier.update(data).digest()

    def verify_mac2(self, data: bytes, mac: bytes) -> None:
        # print('mac2 data: ', mac)
        try:
            self.mac2_verifier.update(data).verify(mac)
        except ValueError:
            raise ValueError

    def handler(self, signum, frame):
        """ handle a SIGINT (ctrl-C) keypress """
        for s in self.in_channels:  # close all sockets
            s.close()
        sys.exit(0)


class SelectServer(GeneralModule):
    def __init__(self, confkey, authkey):
        super(SelectServer, self).__init__(confkey=confkey, authkey=authkey)
        self.socket.bind((self.host, self.port))
        self.socket.listen(3)  # listen up to 3 connections. in this case, 1 is enough

    def wait_for_connection(self) -> socket.socket:
        conn, _ = self.socket.accept()
        self.in_channels.append(conn)
        return conn

    def run(self):
        signal.signal(signal.SIGINT, self.handler)
        while True:
            sock = self.wait_for_connection()

            while self.in_channels:
                readable, _, _ = select.select(self.in_channels, [], [])

                if sock in readable:
                    raw_data = sock.recv(2048)
                    iv, msg_len, mac1, msg, mac2 = raw_data[:16], raw_data[16:32], raw_data[32:64], \
                                                   raw_data[64: -32], raw_data[-32:]
                    # every time, when sending message, the sender generates a new IV
                    # and the receiver gets the IV from the received datastream
                    self.iv = iv
                    self.decryptor = AES.new(self.confkey, AES.MODE_CBC, self.iv)
                    try:
                        self.verify_mac1(iv + msg_len, mac1)
                        self.verify_mac2(msg, mac2)
                        # pass
                    except ValueError:
                        print("ERROR: HMAC verification failed")
                        if sock in self.out_channels:
                            self.out_channels.remove(sock)
                        self.in_channels.remove(sock)
                        sock.close()
                        sys.exit()
                        # break
                    msg_len = int(self.decrypt(msg_len))
                    msg = self.decrypt(msg)
                    if msg_len != len(msg):
                        print('Message Length doesn\'t match')
                    if msg != str(self.iv):
                        sys.stdout.write(msg)
                        sys.stdout.flush()
                # r is sys.stdin, read inputs and send to the client
                if sys.stdin in readable:
                    msg = sys.stdin.readline()
                    self.iv = os.urandom(16)
                    self.encryptor = AES.new(self.confkey, AES.MODE_CBC, self.iv)

                    msg_len = str(len(msg))
                    msg_len = self.encrypt(msg_len)  # iv: 16bytes, msg_len: 16bytes

                    mac1 = self.generate_mac1(self.iv + msg_len)  # mac: 32bytes

                    msg = self.encrypt(msg)
                    mac2 = self.generate_mac2(msg)

                    final_msg = self.iv + msg_len + mac1 + msg + mac2
                    sock.sendall(final_msg)


class SelectClient(GeneralModule):
    """
    The client side of instant messaging service.
    """

    def __init__(self, host: str, confkey: str, authkey: str):
        """
        :param host: the address of server
        :param confkey: the confidential key of AES256
        :param authkey: the authentification key of SHA256 in HMAC
        :param iv: initialization vector to initialize encryptor in CBC mode. Without it, the first message would be lost
        since it is viewed as the iv.
        """
        super(SelectClient, self).__init__(confkey=confkey, authkey=authkey)
        self.dst_host = host
        self.dst_port = 9999

        self.socket.connect((self.dst_host, self.dst_port))

        self.in_channels = [self.socket, sys.stdin]
        # self.out_channels = []

    def run(self):
        signal.signal(signal.SIGINT, self.handler)
        while True:
            readable, _, _ = select.select(self.in_channels, [], [])
            for r in readable:
                # if r is the socket, then receive the message and print
                if r is self.socket:
                    raw_data = r.recv(2048)
                    # print("RAW_MSG: ", msg)
                    iv, msg_len, mac1, msg, mac2 = raw_data[:16], raw_data[16:32], raw_data[32:64], \
                                                   raw_data[64: -32], raw_data[-32:]
                    self.iv = iv
                    self.decryptor = AES.new(self.confkey, AES.MODE_CBC, self.iv)
                    try:
                        self.verify_mac1(iv + msg_len, mac1)
                        self.verify_mac2(msg, mac2)
                    except ValueError:
                        print("ERROR: HMAC verification failed")
                        sys.exit()
                    msg_len = int(self.decrypt(msg_len))
                    msg = self.decrypt(msg)
                    if msg_len != len(msg):
                        print('Message Length doesn\'t match')
                    if msg != str(self.iv):
                        sys.stdout.write(msg)
                        sys.stdout.flush()

                # else means r is the sys.stdin, so read the line then send the message
                else:
                    self.iv = os.urandom(16)
                    self.encryptor = AES.new(self.confkey, AES.MODE_CBC, self.iv)
                    msg = r.readline()
                    msg_len = str(len(msg))
                    msg_len = self.encrypt(msg_len)  # iv: 16bytes, msg_len: 16bytes

                    mac1 = self.generate_mac1(self.iv + msg_len)  # mac: 32bytes

                    msg = self.encrypt(msg)
                    mac2 = self.generate_mac2(msg)
                    final_msg = self.iv + msg_len + mac1 + msg + mac2
                    self.socket.sendall(final_msg)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--s", required=False, action="count",
                        help="If True, then listener; If False, then connector")
    parser.add_argument("--c", type=str, default="localhost", help="The ip address of the listener", required=False)
    parser.add_argument("--confkey", required=False, type=str, default='0' * 32, help="Confidential Key")
    parser.add_argument("--authkey", required=False, type=str, default='1' * 16, help="Authentication Key")
    args = parser.parse_args()

    # The key must be 32 bytes long to use AES-256
    if len(args.confkey.encode()) < 32:
        args.confkey += (32 - len(args.confkey.encode())) * 'a'
    # length of iv must be strictly 16 bytes
    # to be more random, we pick the first 16 bytes from the confkey

    if args.s and args.s >= 1:
        SelectServer(args.confkey, args.authkey).run()
    elif args.c:
        SelectClient(args.c, args.confkey, args.authkey).run()
    else:
        pass
