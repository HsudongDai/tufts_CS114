import os

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
    if len(s) == 0:
        return ""
    return s[:-ord(s[len(s) - 1:])]


class SelectServer:
    def __init__(self, confkey, authkey):
        self.host = 'localhost'
        self.port = 9999

        self.confkey = confkey.encode('utf-8')
        self.authkey = authkey.encode('utf-8')

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(3)  # listen up to 3 connections. in this case, 1 is enough
        # print('listening on 127.0.0.1:9999')

        self.in_channels = [self.socket, sys.stdin]  # list of readable sockets for select
        self.out_channels = []  # list of writable sockets for select

        self.encryptor = None
        self.decryptor = None
        self.mac1_verifier = None
        self.mac2_verifier = None

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

    def generate_mac1(self, data: bytes) -> bytes:
        return self.mac1_verifier.update(data).digest()

    def verify_mac1(self, data: bytes, mac: bytes) -> None:
        # print('mac1 in method: ', data)
        self.mac1_verifier.update(data).verify(mac)

    def generate_mac2(self, data: bytes) -> bytes:
        return self.mac2_verifier.update(data).digest()

    def verify_mac2(self, data: bytes, mac: bytes) -> None:
        # print('mac2 data: ', mac)
        self.mac2_verifier.update(data).verify(mac)
        # sys.exit(-1)

    def run(self):
        while True:
            sock = self.wait_for_connection()
            iv = sock.recv(32)
            self.encryptor = AES.new(self.confkey, AES.MODE_CBC, iv)
            self.decryptor = AES.new(self.confkey, AES.MODE_CBC, iv)
            self.mac1_verifier = HMAC.new(self.authkey, digestmod=SHA256)
            self.mac2_verifier = HMAC.new(self.authkey, digestmod=SHA256)
            while self.in_channels:
                readable, _, _ = select.select(self.in_channels, [], [])

                if sock in readable:
                    raw_data = sock.recv(1500)
                    iv, msg_len, mac1, msg, mac2 = raw_data[:16], raw_data[16:32], raw_data[32:64], \
                                                   raw_data[64: -32], raw_data[-32:]
                    # print('iv: ', iv)
                    # print('msg_len: ', msg_len)
                    # print('mac1: ', mac1)
                    # print('msg: ', msg)
                    # print('mac2: ', mac2)
                    # print("Received data: ", data)
                    try:
                        self.verify_mac1(iv + msg_len, mac1)
                        self.verify_mac2(msg, mac2)
                        # pass
                    except ValueError:
                        print("ERROR: HMAC mac1 verification failed")
                        if sock in self.out_channels:
                            self.out_channels.remove(sock)
                        self.in_channels.remove(sock)
                        sock.close()
                        break
                    msg_len = int(self.decrypt(msg_len))
                    msg = self.decrypt(msg)
                    if msg_len != len(msg):
                        continue
                    # if data == '':
                    #     if sock in self.out_channels:
                    #         self.out_channels.remove(sock)
                    #     self.in_channels.remove(sock)
                    #     sock.close()
                    #     break
                    sys.stdout.write(msg)
                    sys.stdout.flush()
                # r is sys.stdin, read inputs and send to the client
                if sys.stdin in readable:
                    msg = sys.stdin.readline()
                    # print("Server read message: ", msg)
                    if msg is None or msg == "":
                        sys.exit(-1)

                    msg_len = str(len(msg))
                    # print('raw_msg_len: ', msg_len)
                    msg_len = self.encrypt(msg_len)  # iv: 16bytes, msg_len: 16bytes
                    # print('msg_len: ', msg_len)
                    mac1 = self.generate_mac1(iv + msg_len)  # mac: 32bytes
                    # print('mac1: ', mac1)

                    msg = self.encrypt(msg)
                    mac2 = self.generate_mac2(msg)
                    # print('mac2 data: ', mac2)
                    final_msg = iv + msg_len + mac1 + msg + mac2
                    # final_msg = struct.pack(f'16c16c32c{len(msg)}c32c', iv, msg_len, mac1, msg, mac2)

                    sock.sendall(final_msg)


class SelectClient(object):
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
        self.dst_host = host
        self.dst_port = 9999
        self.confkey = confkey.encode('utf-8')
        self.authkey = authkey.encode('utf-8')

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.socket.setblocking(False)
        self.socket.connect((self.dst_host, self.dst_port))

        self.iv = os.urandom(16)
        self.socket.send(self.iv)

        self.in_channels = [self.socket, sys.stdin]
        self.encryptor = AES.new(self.confkey, AES.MODE_CBC, self.iv)
        self.decryptor = AES.new(self.confkey, AES.MODE_CBC, self.iv)
        self.mac1_verifier = HMAC.new(self.authkey, digestmod=SHA256)
        self.mac2_verifier = HMAC.new(self.authkey, digestmod=SHA256)
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

    def generate_mac1(self, data: bytes) -> bytes:
        return self.mac1_verifier.update(data).digest()

    def verify_mac1(self, data: bytes, mac: bytes) -> None:
        # print('mac1 in method: ', data)
        try:
            self.mac1_verifier.update(data).verify(mac)
        except ValueError:
            print("ERROR: HMAC in method 1 verification failed")

    def generate_mac2(self, data: bytes) -> bytes:
        return self.mac2_verifier.update(data).digest()

    def verify_mac2(self, data: bytes, mac: bytes) -> None:
        # print("mac2 data: ", mac)
        try:
            self.mac2_verifier.update(data).verify(mac)
        except ValueError:
            print("ERROR: HMAC in method 2 verification failed")

    def run(self):
        while True:
            readable, _, _ = select.select(self.in_channels, [], [])
            for r in readable:
                # if r is the socket, then receive the message and print
                if r is self.socket:
                    raw_data = r.recv(1536)
                    # print("RAW_MSG: ", msg)
                    iv, msg_len, mac1, msg, mac2 = raw_data[:16], raw_data[16:32], raw_data[32:64], \
                                                   raw_data[64: -32], raw_data[-32:]
                    # print("Received data: ", data)
                    try:
                        self.verify_mac1(iv + msg_len, mac1)
                        self.verify_mac2(msg, mac2)
                        # pass
                    except ValueError:
                        print("ERROR: HMAC verification failed")
                        break
                        # print(msg, flush=True)
                    msg_len = int(self.decrypt(msg_len))
                    msg = self.decrypt(msg)
                    if msg_len != len(msg):
                        continue
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                # else means r is the sys.stdin, so read the line then send the message
                else:
                    msg = r.readline()
                    msg_len = str(len(msg))
                    msg_len = self.encrypt(msg_len)  # iv: 16bytes, msg_len: 16bytes
                    # print('msg_len: ', len(msg_len))
                    mac1 = self.generate_mac1(self.iv + msg_len)  # mac: 32bytes
                    # print('iv + msg_len mac1 ', self.iv + msg_len)
                    # print('mac1: ', len(mac1))

                    msg = self.encrypt(msg)
                    mac2 = self.generate_mac2(msg)
                    # print('mac2 in client: ', mac2)
                    final_msg = self.iv + msg_len + mac1 + msg + mac2
                    # print('iv: ', self.iv)
                    # print('msg_len: ', msg_len)
                    # print('mac1: ', mac1)
                    # print('msg: ', msg)
                    # print('mac2: ', mac2)
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
    # assert len(args.confkey.encode('utf-8')) == 32
    if len(args.confkey.encode('utf-8')) < 32:
        args.confkey += (32 - len(args.confkey.encode('utf-8'))) * 'a'
    # if args.s is False and args.c is not None:
    #     raise AttributeError("s and c cannot be set simultaneously")
    # args.s = 1

    # length of iv must be strictly 16 bytes
    # to be more random, we pick the first 16 bytes from the confkey

    if args.s and args.s >= 1:
        SelectServer(args.confkey, args.authkey).run()
    elif args.c:
        SelectClient(args.c, args.confkey, args.authkey).run()
    else:
        pass
