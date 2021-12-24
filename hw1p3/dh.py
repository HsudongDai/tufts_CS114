import argparse
import random
import select
import signal
import socket
import sys
import numpy as np


class GeneralModule:
    def __init__(self):
        self.host = 'localhost'
        self.port = 9999

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.in_channels = [self.socket, sys.stdin]  # list of readable sockets for select
        self.out_channels = []  # list of writable sockets for select

        # for DH algorithm
        self.g_base = 2
        self.p_prime = 0xcc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

        self.confkey = None

    def handler(self, signum, frame):
        """ handle a SIGINT (ctrl-C) keypress """
        for s in self.in_channels:  # close all sockets
            s.close()
        sys.exit(0)


class SelectServer(GeneralModule):
    def __init__(self):
        super(SelectServer, self).__init__()
        self.socket.bind((self.host, self.port))
        self.socket.listen(3)  # listen up to 3 connections. in this case, 1 is enough

        self.b = None
        self.B = None

        # self.msg_queues = {}                      # one-to-one connection, unnecessary to use a dict for msg queue

    def wait_for_connection(self):
        conn, _ = self.socket.accept()
        self.in_channels.append(conn)
        return conn

    def run(self):
        signal.signal(signal.SIGINT, self.handler)
        sock = self.wait_for_connection()
        self.b = int(random.uniform(0, self.p_prime))

        while self.in_channels:
            readable, _, _ = select.select(self.in_channels, [], [])

            if sock in readable:
                data = sock.recv(1024)
                # data is not none, that is connection has not been broken
                if data:
                    # print(f"Receive message from {r.getpeername()}")
                    # force to flush every message by setting flush=True
                    data = data.decode('utf-8')
                    data = data.strip('\n')
                    if self.confkey is None:
                        A = int(data)
                        self.confkey = pow(A, self.b, self.p_prime)
                        sys.stdout.write(str(self.confkey) + '\n')
                        sys.stdout.flush()

                        self.B = pow(self.g_base, self.b, self.p_prime)
                        sock.sendall(bytes(str(self.B) + '\n', encoding='utf-8'))
                        sys.exit(1)
                    # print(data, flush=True)

                    if sock not in self.out_channels:
                        self.out_channels.append(sock)
                # connection has been broken, sockets must be removed from lists then closed
                else:
                    # print(f"Connection to {r.getpeername()} has been closed")
                    if sock in self.out_channels:
                        self.out_channels.remove(sock)
                    self.in_channels.remove(sock)
                    sock.close()
            # r is sys.stdin, read inputs and send to the client
            if sys.stdin in readable:
                msg = sys.stdin.readline()
                if msg is None or msg == "":
                    break
                sock.sendall(msg.encode('utf-8'))


class SelectClient(GeneralModule):
    def __init__(self, host):
        super(SelectClient, self).__init__()
        # self.socket.setblocking(False)
        self.host = host
        self.socket.connect((self.host, self.port))

        self.in_channels = [self.socket, sys.stdin]
        # self.out_channels = []

        self.a = None
        self.A = None

    def run(self):
        signal.signal(signal.SIGINT, self.handler)
        self.a = int(random.uniform(0, self.p_prime))
        self.A = pow(2, self.a, self.p_prime)
        self.socket.sendall(bytes(str(self.A) + '\n', encoding='utf-8'))
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
                        msg = msg.decode('utf-8')
                        msg = msg.strip('\n')
                        if self.confkey is None:
                            B = int(msg)
                            self.confkey = pow(B, self.a, self.p_prime)
                            sys.stdout.write(str(self.confkey) + '\n')
                            sys.stdout.flush()

                            sys.exit(1)
                        # print(msg, flush=True)

                # else means r is the sys.stdin, so read the line then send the message
                else:
                    msg = r.readline()
                    if msg[-1] != '\n':
                        try:
                            msg += '\n'
                        except IndexError:
                            sys.exit(-1)

                    self.socket.sendall(msg.encode('utf-8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--s", required=False, action="count",
                        help="If True, then listener; If False, then connector")
    parser.add_argument("--c", type=str, default="localhost", help="The ip address of the listener", required=False)
    args = parser.parse_args()

    # if args.s is False and args.c is not None:
    #     raise AttributeError("s and c cannot be set simultaneously")

    if args.s and args.s >= 1:
        SelectServer().run()
    elif args.c:
        SelectClient(args.c).run()
    else:
        pass
