import socket
import ssftp
from threading import Thread
from time import sleep

import logging
import sys

MAX_CONNECTIONS = 1
# Max data length is 2^16 so just adding a few bytes for good measure
MAX_MESSAGE_LENGTH = 2**16 + 2**8

MESSAGE_TIMEOUT_MS = 500
MESSAGE_READ_INTERVAL_MS = 20

ENABLE_LOGGING = True


class SSFTPServer():
    def __init__(self):
        self.max_connections = MAX_CONNECTIONS
        # dict containing connections, states, and options for each one
        # two possible states: 0 - idle, 1 - smth's happening aka data transfer
        #   _Address: { state: 0|1,  options: {opts:here,} }
        self.connections = dict()
        self.ipv4addr = None

        self.new_conn_socket = None
        self._new_conn_listener_thread = None

        # on a new connection, a listener thread is created.
        self._listener_threads = dict()

        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)
        self.logger.disabled = False

    # =======================
    # MESSAGE HANDLING
    # =======================

    def _message_mux(self, msg: bytes, addr: tuple):
        opcode_bytes = msg[0:2]
        opcode = int.from_bytes(opcode_bytes, 'big')

        if (opcode == ssftp.OPCODE.SYN.value.get_int()):
            self._handle_syn(msg=msg, addr=addr)
        # server should be SENDING, not receiving a SYNACK
        elif (opcode == ssftp.OPCODE.SYNACK.value.get_int()):
            pass
        elif (opcode == ssftp.OPCODE.DWN.value.get_int()):
            pass
        elif (opcode == ssftp.OPCODE.UPL.value.get_int()):
            pass
        elif (opcode == ssftp.OPCODE.OACK.value.get_int()):
            pass
        elif (opcode == ssftp.OPCODE.ERR.value.get_int()):
            pass
        elif (opcode == ssftp.OPCODE.ACK.value.get_int()):
            pass
        elif (opcode == ssftp.OPCODE.DATA.value.get_int()):
            pass
        elif (opcode == ssftp.OPCODE.FIN.value.get_int()):
            pass
        elif (opcode == ssftp.OPCODE.FINACK.value.get_int()):
            pass

        print(f"opcode: {opcode}")

    def _handle_syn(self, msg: bytes, addr: tuple):
        self.logger.info(f"Incoming connection from {addr}")
        if addr in self.connections:
            self.logger.info(f"{addr} already in connections. Disregarding.")
            return
        if len(self.connections) >= MAX_CONNECTIONS:
            self.logger.info("Max number of connections reached. Disregarding.")
            return

        # add to connections and respond
        self.connections[addr] = {"state": 0, "options": dict()}

        # create new connection socket
        conn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn_sock.bind((self.ipv4addr, 0))
        conn_sock.setblocking(False)

        new_connection_thread = Thread(target=lambda: self._listener(addr, conn_sock))
        self._listener_threads[addr] = new_connection_thread
        self._listener_threads[addr].start()

        print(self.connections)

    # =========================
    # Listener Functions
    # =========================

    # Thread for listening for NEW connections
    def _new_conn_listener(self):
        if self.new_conn_socket is None:
            return False

        while self.new_conn_socket is not None:
            try:
                data, addr = self.new_conn_socket.recvfrom(4)
                self._message_mux(data, addr)
                if MESSAGE_READ_INTERVAL_MS > 0:
                    sleep(1 / MESSAGE_READ_INTERVAL_MS)
            except socket.error:
                if MESSAGE_TIMEOUT_MS > 0:
                    sleep(1 / MESSAGE_TIMEOUT_MS)

    # Starts listening for NEW connections.
    def new_conn_listen(self):
        if self.new_conn_socket is not None or self._new_conn_listener_thread is not None:
            return

        # getting ip
        if self.ipv4addr is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            try:
                s.connect(('10.255.255.255', 1))
                self.ipv4addr = s.getsockname()[0]
            except Exception:
                self.ipv4addr = '127.0.0.1'
            finally:
                s.close()

        # socket creation and binding
        self.new_conn_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.new_conn_socket.bind((self.ipv4addr, ssftp.SERVER_LISTEN_PORT))
        self.new_conn_socket.setblocking(False)

        self._new_conn_listener_thread = Thread(target=self._new_conn_listener)
        self._new_conn_listener_thread.start()

    # listens for messages on a specific socket assocaited with a connection
    # used as the target method for new connections.
    # target addr used to check in while loop to ensure the conneciton is
    # still alive
    def _listener(self, target_addr, conn_socket):
        # using the new_conn_socket as a condition
        if self.new_conn_socket is None:
            return False
        while target_addr in self._listener_threads.keys():
            try:
                data, addr = conn_socket.recvfrom(MAX_MESSAGE_LENGTH)
                if addr != target_addr:
                    self.logger.info("Recevied message from a different address than target address. Discarding.")
                    continue
                self._message_mux(data, addr)
                if MESSAGE_READ_INTERVAL_MS > 0:
                    sleep(1 / MESSAGE_READ_INTERVAL_MS)
            except socket.error:
                if MESSAGE_TIMEOUT_MS > 0:
                    sleep(1 / MESSAGE_TIMEOUT_MS)

    def listen(self):
        pass

    def close(self):
        self.new_conn_socket.close()
        self.new_conn_socket = None
        self._new_conn_listener_thread = None


if __name__ == "__main__":
    ssftpserver = SSFTPServer()

    ssftpserver.new_conn_listen()
    sockname = ssftpserver.new_conn_socket.getsockname()

    while True:
        pass
