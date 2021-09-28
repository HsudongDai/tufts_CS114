import argparse
import select
import signal
import socket
import threading


class IMServer(object):
    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 9999

        # signal.signal(signal.SIGINT, self.handler)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(True)
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)  # listen to most 10 connections
        # print('listening on 127.0.0.1:9999')

        # self.in_channels = [self.socket]
        # self.out_channels = []

    def link(self, sock, addr):
        # sock.send("Welcome to Chat Server".encode('utf-8'))
        sock.send(" ".encode('utf-8'))
        while True:
            data = sock.recv(1024).decode('utf-8')
            # print(sock.getpeername())
            # print(sock.getsockname())
            # if data == 'break':
            #     break
            if data is not None:
                print(data)
                response = self.get_response()
                sock.sendall(response.encode('utf-8'))
        sock.close()
        print('Chat is done')

    def get_response(self):
        msg = input()
        return msg

    def run(self):
        while True:
            sock, addr = self.socket.accept()
            # thrd = threading.Thread(target=self.link, args=(sock, addr))
            # thrd.start()

    def handler(self):
        self.socket.close()
    # def run(self):
    #     print(f"IM Server is running on {self.host}:{self.port}")
    #     sock, addr = self.socket.accept()
    #     while True:
    #         msg = sock.recv(1024)
    #         print(msg.decode(encoding='utf-8'))
    #         if msg == b'bye':
    #             sock.send(b'bye')
    #             break
    #         info = input('>>>')
    #         sock.send(bytes(info+'\n', encoding='utf-8'))
    #     sock.close()
    #     self.socket.close()

    # def run(self):
    #     print(f"IM Server is running on {self.host}:{self.port}")
    #     sread, _, _ = select.select(self.descriptors, [], [])
    #
    #     while True:
    #         for sock in sread:
    #             if sock == self.socket:
    #                 self._build_connection()
    #             else:
    #                 msg = sock.recv(1024)
    #                 print(msg.decode('utf-8'))
    #                 info = input()
    #                 sock.send(bytes(info + '\n', encoding='utf-8'))
    #                 sys.stdout.flush()
    #                 if msg == 'bye':
    #                     host, port = sock.getpeername()
    #                     leavingMsg = f"Client {host}:{port} has left."
    #                     print(leavingMsg)
    #                     sock.close()
    #                     self.descriptors.remove(sock)
    #                 else:
    #                     host, port = sock.getpeername()
    #                     cliMsg = f"[{host}:{port}]: {msg.decode('utf-8')}"
    #                     print(cliMsg)
    #                     svrMsg = input(">>>")
    #                     sock.send(bytes(svrMsg, encoding='utf-8'))
    #
    #     self.socket.close()

    # def _build_connection(self):
    #     sock, (cli_host, cli_port) = self.socket.accept()
    #     self.descriptors.append(sock)
    #     sock.send(bytes("You have been connected to the server", encoding="utf-8"))
    #     print(f'Client {cli_host}:{cli_port} has connected to the server')
    #
    # def _broadcast_message(self, msg):
    #     for sock in self.descriptors:
    #         if sock != self.socket:
    #             sock.send(bytes(msg, encoding='utf-8'))


class IMClient(object):
    def __init__(self, host):
        self.host = host
        self.port = 9999
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(False)
        self.socket.connect((self.host, self.port))

    def send_message(self, msg):
        self.socket.sendall(msg.encode('utf-8'))

    def receive_message(self):
        data = self.socket.recv(1024)
        if data:
            print(data.decode('utf-8'))
            return True
        return False

    def run(self):
        data = self.socket.recv(1024)
        print(data.decode('utf-8'))
        msg = input()
        self.send_message(msg)
        while True:
            if self.receive_message():
                msg = input()
                self.send_message(msg)
                if msg == 'break':
                    break
                while True:
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
