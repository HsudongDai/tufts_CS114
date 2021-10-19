# hw1p1.py
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

import argparse
import select
import socket
import sys
import signal

# define some globals
HOST = ''
PORT = 9999
SOCKET_LIST = []

BLOCK_SIZE = AES.block_size


def pad(s: str) -> str:
    padding = (BLOCK_SIZE - len(s.encode("utf-8")) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s.encode("utf-8")) % BLOCK_SIZE)
    return s + padding


def unpad(s: str) -> str:
    return s[:-ord(s[len(s) - 1:])]


def handler(signum, frame):
    """ handle a SIGINT (ctrl-C) keypress """
    for s in SOCKET_LIST:  # close all sockets
        s.close()
    sys.exit(0)


def wait_for_incoming_connection():
    """
    create a server socket and wait for incoming connection

    returns the server socket
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    SOCKET_LIST.append(s)
    SOCKET_LIST.append(conn)
    return conn


def connect_to_host(dst):
    """ connects to the host 'dst' """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((dst, PORT))
        SOCKET_LIST.append(s)
        return s
    except socket.error:
        print("Could not connect to %s." % dst)
        sys.exit(0)


def encrypt(encryptor, msg: str) -> bytes:
    padded_msg = pad(msg)
    # print('Padded msg:', padded_msg.encode('utf-8'))
    enc_msg = encryptor.encrypt(padded_msg.encode("utf-8"))
    # print('Encrypted msg: ', enc_msg)
    return enc_msg


def decrypt(decryptor, enc_msg: bytes) -> str:
    # print("enc_msg is: ", enc_msg)
    temp = decryptor.decrypt(enc_msg)
    # print("decrypted msg is: ", temp)
    enc_msg = unpad(temp.decode("utf-8"))
    # print("unpadded msg: ", enc_msg)
    return enc_msg


def generate_mac(verifier, data: bytes) -> bytes:
    return verifier.update(data).digest()


def verify_mac(verifier, data: bytes, mac: bytes) -> None:
    verifier.update(data).verify(mac)


def parse_command_line():
    """ parse the command-line """
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--c", dest="dst", help="destination address")
    parser.add_argument("-s", "--s", dest="server", action="store_true",
                        default=False, help="start server mode")
    parser.add_argument("--confkey", required=False, type=str, default='0' * 32, help="Confidential Key")
    parser.add_argument("--authkey", required=False, type=str, default='1' * 16, help="Authentication Key")

    options = parser.parse_args()

    if not options.dst and not options.server:
        parser.print_help()
        parser.error("must specify either server or client mode")

    return options


if __name__ == "__main__":

    options = parse_command_line()

    # catch when the user presses CTRL-C
    signal.signal(signal.SIGINT, handler)

    if options.server:
        s = wait_for_incoming_connection()
    elif options.dst:
        s = connect_to_host(options.dst)
    else:
        assert (False)  # this shouldn't happen

    iv = options.confkey.encode('utf-8')[:16]

    encryptor = AES.new(options.confkey, AES.MODE_CBC, iv)
    decryptor = AES.new(options.confkey, AES.MODE_CBC, iv)
    verifier = HMAC.new(options.authkey, digestmod=SHA256)

    rlist = [s, sys.stdin]
    wlist = []
    xlist = []

    while True:
        (r, w, x) = select.select(rlist, wlist, xlist)
        if s in r:  # there is data to read from network
            data = s.recv(1536)
            msg, mac = data[:-32], data[-32:]
            verify_mac(verifier, msg, mac)
            msg = decrypt(decryptor, msg)
            if msg == "":  # other side ended connection
                break
            sys.stdout.write(msg)
            sys.stdout.flush()

        if sys.stdin in r:  # there is data to read from stdin
            data = sys.stdin.readline()
            if data == "":  # we closed STDIN
                break
            msg = encrypt(encryptor, data)
            mac = generate_mac(verifier, msg)
            msg += mac
            s.send(msg)

    """
            If we get here, then we've got an EOF in either stdin or our network.
            In either case, we iterate through our open sockets and close them.
    """
    for sock in SOCKET_LIST:
        sock.close()

    sys.exit(0)  # all's well that ends well!
