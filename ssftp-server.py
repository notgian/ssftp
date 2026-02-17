import socket
import ssftp
from threading import Thread
from time import sleep


MAX_CONNECTIONS = 1
# Max data length is 2^16 so just adding a few bytes for good measure
MAX_MESSAGE_LENGTH = 2**16 + 2**8


class SSFTPServer():
    def __init__(self):
        self.max_connections = MAX_CONNECTIONS
        # an array that contains the addresses to each connection
        self.connections = []

        self.socket = None
        self._listener_thread = None

    def _message_mux(self):
        pass

    def _listener(self):
        if self.socket is None:
            return False

        while self.socket is not None:
            try:
                data = self.socket.recv(131072)
                print(data.decode())
                sleep(0.5)
            except socket.error:
                pass

    def listen(self):
        if self.socket is not None or self._listener_thread is not None:
            return

        # getting ip
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        ipaddr = None
        try:
            s.connect(('10.255.255.255', 1))
            ipaddr = s.getsockname()[0]
        except Exception:
            ipaddr = '127.0.0.1'
        finally:
            s.close()

        # socket creation and binding
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.socket.bind((ipaddr, ssftp.SERVER_LISTEN_PORT))
        self.socket.setblocking(False)

        self._listener_thread = Thread(target=self._listener)
        self._listener_thread.start()

    def close(self):
        self.socket.close()
        self.socket = None
        self._listener_thread = None


if __name__ == "__main__":
    ssftpserver = SSFTPServer()

    ssftpserver.listen()
    sockname = ssftpserver.socket.getsockname()
    print(f"Started listening on {sockname[0]}:{sockname[1]}...")

    while True:
        pass
