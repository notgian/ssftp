import socket


if __name__ == "__main__":
    socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    socket.bind(('', 4000))

    socket.sendto("abcd".encode(), ("192.168.68.70", 3900))
