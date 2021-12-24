import argparse
import socket, sys


class Client:
    def __init__(self, host):
        self.host = '127.0.0.1'
        self.port = 9999
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    def run(self):
        try:
            self.s.connect((self.host, self.port))
        except socket.gaierror as e:
             print("Address-related error connecting to server: %s" %e)
             sys.exit(1)
        except socket.error as e:
            print("Connection error: %s" %e)
            sys.exit(1)
        while 1:
            try:
                data = input()
                self.s.send(bytes(data+'\n', encoding='utf-8'))
                buf = self.s.recv(1024)
                if len(buf):
                    print(buf.decode(encoding='utf-8'))
                sys.stdout.flush()
            except Exception:
                print("Dialogue Over")
                self.s.close()
                sys.exit(0)

class Server:

    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 9999
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((self.host, self.port))
        self.s.listen(1)

    def run(self):
        ClientSock, ClientAddr = self.s.accept()
        while 1:
            try:
                buf = ClientSock.recv(1024)
                if len(buf):
                    print(buf.decode('utf-8'))
                    sys.stdout.flush()
                data = input()
                ClientSock.sendall(bytes(data+'\n', encoding='utf-8'))
            except Exception:
                print("Dialogue Over")
                ClientSock.close()
                sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--s", required=False, action="count",
                        help="If True, then listener; If False, then connector")
    parser.add_argument("--c", type=str, default="127.0.0.1", help="The ip addr of the listener", required=False)
    args = parser.parse_args()

    # if args.s is False and args.c is not None:
    #     raise AttributeError("s and c cannot be set simultaneously")

    if args.s is not None and args.s >= 1:
        Server().run()

    if args.c:
        Client(args.c).run()
