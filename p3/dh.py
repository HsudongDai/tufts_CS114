import argparse
import select
import signal
import socket
import sys


class GeneralModule:
    def __init__(self):
        self.host = 'localhost'
        self.port = 9999

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.in_channels = [self.socket, sys.stdin]  # list of readable sockets for select
        self.out_channels = []  # list of writable sockets for select

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

        # self.msg_queues = {}                      # one-to-one connection, unnecessary to use a dict for msg queue

    def wait_for_connection(self):
        conn, _ = self.socket.accept()
        self.in_channels.append(conn)
        return conn

    def run(self):
        signal.signal(signal.SIGINT, self.handler)
        sock = self.wait_for_connection()
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
                    data += '\n'
                    sys.stdout.write(data)
                    sys.stdout.flush()
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

    def run(self):
        signal.signal(signal.SIGINT, self.handler)
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
