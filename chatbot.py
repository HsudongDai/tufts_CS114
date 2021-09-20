import argparse
import socket
import time
import threading


class ChatServer:
    def __init__(self, port):
        # 绑定服务器的ip和端口，注意以tuple的形式
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", port))
        self.socket.listen(5)
        # 图灵机器人，授权码
        # self.key = "your tuling robot key"
        print("正在监听 127.0.0.1 ：{}...".format(port))

    def tcplink(self, sock, addr):
        # 每次连接，开始聊天前，先欢迎下。
        sock.send("你好，欢迎来到机器人聊天器！".encode("utf-8"))
        while True:
            data = sock.recv(1024).decode("utf-8")
            print(sock.getpeername())
            print(sock.getsockname())
            print(sock.fileno())
            username = data.split("::")[0]
            msg = data.split("::")[1]
            if msg == "exit":
                break
            if msg:
                print("【" + username + "】 " + time.strftime('%Y-%m-%d:%H:%M:%S', time.localtime(time.time())))
                print(msg)
                response = self.get_response()
                sock.send(response.encode("utf-8"))
        sock.close()
        print("与 {} 结束聊天！".format(username))

    def get_response(self):
        msg = input("请输入消息：")
        return msg
        # # 调用图灵机器人API
        # url = 'http://www.tuling123.com/openapi/api?key=' + self.key + '&info=' + info
        # res = requests.get(url)
        # res.encoding = 'utf-8'
        # jd = json.loads(res.text)
        # return jd['text']

    def main(self):
        while True:
            sock, addr = self.socket.accept()
            t = threading.Thread(target=self.tcplink, args=(sock, addr))
            t.start()


class ChatClient:
    def __init__(self, username, port):
        self.username = username
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(("127.0.0.1", port))

    def send_msg(self, msg):
        self.socket.send("{username}::{msg}".format(username=self.username, msg=msg).encode("utf-8"))

    def recv_msg(self):
        data = self.socket.recv(1024)
        if data:
            print("\n【机器人小图】" + " " + time.strftime('%Y-%m-%d:%H:%M:%S', time.localtime(time.time())))
            print(data.decode("utf-8"))
            return True
        return False

    def main(self):
        data = self.socket.recv(1024)
        print(data.decode("utf-8"))
        msg = input("请输入消息：")
        self.send_msg(msg)
        while True:
            if self.recv_msg():
                msg = input("\n我：")
                self.send_msg(msg)
                if msg == "exit":
                    print("聊天室已关闭")
                    break


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--s", required=False, action="count",
                        help="If True, then listener; If False, then connector")
    parser.add_argument("--c", type=str, default="127.0.0.1", help="The ip addr of the listener", required=False)
    args = parser.parse_args()

    # if args.s is False and args.c is not None:
    #     raise AttributeError("s and c cannot be set simultaneously")

    if args.s is not None and args.s >= 1:
        ChatServer(9999).main()

    if args.c:
        ChatClient("June", 9999).main()
