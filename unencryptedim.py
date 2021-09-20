import argparse
import select
import signal
import socket
import sys


class SelectServer:
    def __init__(self):
        self.host = 'localhost'
        self.port = 9999

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
                    self.in_channels[-1].sendall(msg.encode('utf-8'))
                # the connection to the client which has been built,
                else:
                    data = r.recv(1024)
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
    def __init__(self, host):
        self.dst_host = host
        self.dst_port = 9999

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.socket.setblocking(False)
        self.socket.connect((self.dst_host, self.dst_port))

        self.in_channels = [self.socket, sys.stdin]
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
