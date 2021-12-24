import argparse
import socket
import select


class IMServer:
    def __init__(self):
        self.port = 9999

        self.srvsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srvsock.bind(("127.0.0.1", self.port))
        self.srvsock.listen(5)

        self.descriptors = [self.srvsock]
        print('ChatServer started on port %s' % self.port)

    def run(self):

        while 1:

            # Await an event on a readable socket descriptor
            sread, swrite, sexc = select.select(self.descriptors, [], [])

            # Iterate through the tagged read descriptors
            for sock in sread:

                # Received a connect to the server (listening) socket
                if sock == self.srvsock:
                    self.accept_new_connection()
                else:

                    # Received something on a client socket
                    str = sock.recv(100)

                    # Check to see if the peer socket closed
                    if str == '':
                        host, port = sock.getpeername()
                        str = 'Client left %s:%s\r\n' % (host, port)
                        self.broadcast_string(str, sock)
                        sock.close()
                        self.descriptors.remove(sock)
                    else:
                        host, port = sock.getpeername()
                        newstr = '[%s:%s] %s' % (host, port, str)
                        self.broadcast_string(newstr, sock)

    def accept_new_connection(self):

        newsock, (remhost, remport) = self.srvsock.accept()
        self.descriptors.append(newsock)

        newsock.send(b"You're connected to the Python chatserver\r\n")
        str = 'Client joined %s:%s\r\n' % (remhost, remport)
        self.broadcast_string(str, newsock)

    def broadcast_string(self, str, omit_sock):
        for sock in self.descriptors:
            if sock != self.srvsock and sock != omit_sock:
                sock.send(str)
        print(str)


class IMClient(object):
    def __init__(self, host):
        self.host = host
        self.port = 9999
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        try:
            self.socket.connect((self.host, self.port))
        except Exception:
            raise Exception
        while True:
            info = input()
            self.socket.send(bytes(info + '\n', encoding='utf-8'))
            msg = self.socket.recv(1024)
            print(msg.decode('utf-8'))
            if msg == b'bye':
                break

        self.socket.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--s", required=False, action="count",
                        help="If True, then listener; If False, then connector")
    parser.add_argument("--c", type=str, default="127.0.0.1", help="The ip addr of the listener", required=False)
    args = parser.parse_args()

    # if args.s is False and args.c is not None:
    #     raise AttributeError("s and c cannot be set simultaneously")

    if args.s is not None and args.s >= 1:
        IMServer().run()

    if args.c:
        IMClient(args.c).run()
