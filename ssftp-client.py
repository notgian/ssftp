import socket
import ssftp
from threading import Thread
from time import sleep

import concurrent.futures
import logging
import sys
import os
import re
import signal

# Max data length is 2^16 so just adding a few bytes for good measure
MAX_MESSAGE_LENGTH = 2**16 + 2**8
MAX_RETRIES = 10

MESSAGE_TIMEOUT_MS = 500
MESSAGE_READ_INTERVAL_MS = 20

# MAX_BLKSIZE = 65464   # 2**16
MAX_BLKSIZE = 4096    # 2**12
# MAX_BLKSIZE = 512    # 2**8

MAX_TIMEOUT_MS = 3000
MIN_TIMEOUT_MS = 200

ENABLE_LOGGING = True


class SSFTPClient():
    def __init__(self):
        # dict of connection containing states and options
        # two possible states: 0 - idle, 1 - smth's happening aka data transfer
        #   _server_address: { state: 0|1,  options: {opts:here,} }
        self.connection = dict()
        self.ipv4addr = None

        self.socket = socket.socket(type=socket.AF_INET, family=socket.SOCK_DGRAM)
        self.socket.bind(('', 0))
        self.portnum = self.socket.getsockname()[1]

        self._listener_thread = None

        # on a new connection, a listener thread is created.

        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)
        self.logger.disabled = False

        # This exit handler will allow us to send a fin to the server
        # before dying in the case a SIGINT is sent to the program
        def exit_handler(signum, frame):
            if len(self.connection) > 0:
                addr = self.connection.keys()[0]
                self.logger.info(f"Forceful termination of program. Disconnecting from {addr}")
                exitcode = ssftp.EXITCODE.FORCEFUL_TERMINATION
                fin = ssftp.MSG_FIN(exitcode)
                self.socket.sendto(fin.encode(), addr)
                self.disconnect(addr=addr, exit_code=exitcode)
            exit(0)
        signal.signal(signal.SIGINT, exit_handler)

    # =======================
    # MESSAGE HANDLING
    # =======================

    def _message_mux(self, message: bytes, address: tuple):
        opcode_bytes = message[0:2]
        opcode = int.from_bytes(opcode_bytes, 'big')
        print(f"opcode: {opcode}")

        # server should be SENDING, not receiving a SYNACK
        if (opcode == ssftp.OPCODE.SYNACK.value.get_int()):
            self._handle_synack(message, address)
            return

        # the following operations require an existing connection
        if address not in self.connection:
            self.logger.info(f"Received message from {address} who is not server. Disregarding.")
            return

        # server should be SENDING, not receiving an OACK
        elif (opcode == ssftp.OPCODE.OACK.value.get_int()):
            self._handle_oack(message, address)

        # a server MAY receive an ERR message
        elif (opcode == ssftp.OPCODE.ERR.value.get_int()):
            self._handle_err(message, address)

        elif (opcode == ssftp.OPCODE.ACK.value.get_int()):
            self._handle_ack(message, address)
        elif (opcode == ssftp.OPCODE.DATA.value.get_int()):
            self._handle_data(message, address)

        elif (opcode == ssftp.OPCODE.FIN.value.get_int()):
            self._handle_fin(message, address)
        elif (opcode == ssftp.OPCODE.FINACK.value.get_int()):
            self._handle_finack(message, address)

    def _handle_synack(self, msg: bytes, addr: tuple):
        if addr in self.connection:
            self.logger.info(f"Already connected to {addr}. Disregarding.")
            return
        elif len(self.connection) > 0:
            self.logger.info(f"Already connected to a server. Disregarding {addr}.")
            return

        ipaddr = addr[0]
        print(msg)
        newport = int.from_bytes(msg[2:6], 'big')
        newaddr = (ipaddr, newport)

        # add to connections and start listening
        connection_thread = Thread(target=lambda: self._listener(newaddr))
        self._listener_thread = connection_thread
        self._listener_thread.start()
        self.connection[newaddr] = {"state": 0, "options": dict()}

        self.logger.info(self.connection)

    def _handle_ack(self, msg, addr):
        seqnum = int.from_bytes(msg[2:4], 'big')
        # discard out-of-order segment
        if self.connections[addr]["options"]["block"] != seqnum-1:
            self.logger.info(f"Received out-of-order segment (seqnum={seqnum}) from {addr}. Discarding.")
            return

        self.connections[addr]["options"]["pending_ack"] += 1

        # check if last block sent was a terminating block and reset state
        # this marks the end of a transaction
        if self.connections[addr]["options"]["terminating_block"]:
            self.connections[addr]["state"] = 0
            self.connections[addr]["options"] = dict()

        # send next segment
        else:
            opts = self.connections[addr]["options"]

            opts["block"] += 1
            d_start = (opts["block"]-1) * opts["blksize"]

            f = open(opts["filepath"], 'rb')
            f.seek(d_start)
            d_send = f.read(opts["blksize"])

            # determine if current segment is terminating
            if len(d_send) < opts["blksize"]:
                opts["terminating_block"] = True
                self.logger.info("End of file reached!")

            # nextdata = ssftp.MSG_DATA(seq_num=opts["block"], data=d_send)
            # self.connections[addr]["socket"].sendto(nextdata.encode(), addr)

            self.thread_pool.submit(self._send_data, opts["block"], d_send, addr)

    def _send_data(self, seqnum: int, data: bytes, addr: tuple):
        retries = 0
        timeout = self.connections[addr]["options"]["timeout"]

        while retries <= MAX_RETRIES:
            nextdata = ssftp.MSG_DATA(seq_num=seqnum, data=data)
            self.connections[addr]["socket"].sendto(nextdata.encode(), addr)
            sleep(timeout/1000)
            pending_ack = self.connections[addr]["options"]["pending_ack"]
            if seqnum+1 < pending_ack:
                break

            retries += 1
            if retries <= MAX_RETRIES:
                self.logger.info(f"No ack({seqnum+1}) received from {addr}. Retrying in {timeout} ms. ({retries}/{MAX_RETRIES})")

        if retries > MAX_RETRIES:
            self.logger.info(f"Max retries reached. Forcefully disconnectiong from {addr}")
            fin = ssftp.MSG_FIN(ssftp.EXITCODE.CONNECTION_LOST)
            self.connections[addr]["socket"].sendto(fin.encode(), addr)

            self.disconnect(addr=addr, exit_code=ssftp.EXITCODE.CONNECTION_LOST)

    def _handle_data(self, msg, addr):
        seq_num = int.from_bytes(msg[2:4], 'big')

        if seq_num != self.connections[addr]["options"]["block"]:
            self.logger.info("Received out-of-order segment. Discarding.")

        data = msg[4:-1]  # excluding the final 0 byte

        # TODO: UNCOMMENT THE LINE BELOW TO USE THE ACTUAL FILENAME
        filename = self.connections[addr]["options"]["filename"]
        # for testing purposes, we will use a different filename
        # filename = 'uploaded.out'

        with open(filename, 'ab') as f:
            f.write(data)

        self.connections[addr]["options"]["block"] += 1
        ack = ssftp.MSG_ACK(self.connections[addr]["options"]["block"])
        self.connections[addr]["socket"].sendto(ack.encode(), addr)

        # this marks the end of a transaction
        if len(data) < self.connections[addr]["options"]["blksize"]:
            self.connections[addr]["state"] = 0
            self.connections[addr]["options"] = dict()
            self.logger.info("End of file reached!")

    def _handle_fin(self, msg, addr):
        # check if connection has an ongoing transaction. If upl, delete the file.
        if self.connections[addr]["state"] == 1:
            if self.connections[addr]["options"]["op"] == ssftp.OPCODE.UPL.value.get_int():
                self.logger.info("FIN messsage from {addr} is interrupting an upload. Aborting upload!")
                upl_filename = self.connections[addr]["options"]["filename"]
                os.remove(upl_filename)

        # disconnect
        exit_code = int.from_bytes(msg[2:4], 'big')
        self.disconnect(addr=addr, exit_code=exit_code)

    def _handle_finack(self, msg, addr):
        pass

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
                opcode = int.from_bytes(data[:2], 'big')
                # skip non syn messages
                if opcode != ssftp.OPCODE.SYN.value.get_int():
                    continue
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

        self._new_conn_listener_thread = Thread(target=self._new_conn_listener, daemon=True)
        self._new_conn_listener_thread.start()

    # listens for messages on a specific socket assocaited with a connection
    # used as the target method for new connections.
    # target addr used to check in while loop to ensure the conneciton is
    # still alive
    def _listener(self, target_addr):
        if len(self.connection) == 0:
            return False

        while len(self.connection) > 0:
            try:
                data, addr = self.socket.recvfrom(MAX_MESSAGE_LENGTH)
                if addr != target_addr:
                    self.logger.info("Recevied message from a different address than target address. Discarding.")
                    continue
                self._message_mux(data, addr)
                if MESSAGE_READ_INTERVAL_MS > 0:
                    sleep(1 / MESSAGE_READ_INTERVAL_MS)
            except socket.error:
                if MESSAGE_TIMEOUT_MS > 0:
                    sleep(1 / MESSAGE_TIMEOUT_MS)
        self.logger.info(f"Listener for {target_addr} stopped.")

    def connect_to(self, addr: tuple):
        if len(self.connection) > 1:
            self.logger.info(f"Connect failed! Already connected to {addr}.")
            return

        syn = ssftp.MSG_SYN()
        self.socket.sendto(syn.encode(), addr)

        # wait for synack
        msg, retaddr = self.socket.recvfrom(MAX_MESSAGE_LENGTH)
        self._message_mux(msg, retaddr)

    def disconnect(self, addr: tuple, exit_code: ssftp.EXITCODE):
        del self.connection[addr]
        self._listener_thread = None
        self.logger.info(f"Closed connection to {addr} with exit code {exit_code}")

    def close(self):
        self.new_conn_socket.close()
        self.new_conn_socket = None
        self._new_conn_listener_thread = None


if __name__ == "__main__":
    known_server = ('192.168.68.70', ssftp.SERVER_LISTEN_PORT)
    ssftpclient = SSFTPClient()

    ssftpclient.connect_to(known_server)

    sockname = ssftpclient.socket.getsockname()

    while True:
        pass
