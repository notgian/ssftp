import socket
import hashlib
import ssftp
from threading import Thread
from time import sleep

import concurrent.futures
import logging
import sys
import os
import re
import signal

MAX_CONNECTIONS = 1
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

DEBUG_PACKET_DELAY = 1000


class SSFTPServer():
    def __init__(self, logger_stream=sys.stdout):
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

        handler = logging.StreamHandler(logger_stream)
        handler.setLevel(logging.INFO)

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)
        self.logger.disabled = False

        # This option is only for testing. Drop packets takes precedence.
        self.drop_packets = False
        self.delay_packets = False

        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONNECTIONS)

        # This exit handler will allow us to send a fin to the client(s)
        # before dying in the case a SIGINT is sent to the program
        def exit_handler(signum, frame):
            connection_addrs = [addr for addr in self.connections]
            for addr in connection_addrs:
                self.logger.info(f"Forceful termination of program. Disconnecting from {addr}")
                exitcode = ssftp.EXITCODE.FORCEFUL_TERMINATION
                fin = ssftp.MSG_FIN(exitcode)
                self.connections[addr]["socket"].sendto(fin.encode(), addr)
                self.disconnect(addr=addr, exit_code=exitcode)
            exit(0)
        signal.signal(signal.SIGINT, exit_handler)

    def kill(self):
        signal.raise_signal(signal.SIGINT)

    # =======================
    # MESSAGE HANDLING
    # =======================

    def _message_mux(self, message: bytes, address: tuple):
        opcode_bytes = message[0:2]
        opcode = int.from_bytes(opcode_bytes, 'big')
        # print(f"opcode: {opcode}")

        if (opcode == ssftp.OPCODE.SYN.value.get_int()):
            self._handle_syn(message, address)

        # the following operations require an existing connection
        if address not in self.connections:
            self.logger.info(f"Received message from {address} who is not connected. Disregarding.")
            return

        if (opcode == ssftp.OPCODE.DWN.value.get_int()):
            self._handle_dwn_upl(message, address)
        elif (opcode == ssftp.OPCODE.UPL.value.get_int()):
            self._handle_dwn_upl(message, address)

        # a server MAY receive an ERR message
        elif (opcode == ssftp.OPCODE.ERR.value.get_int()):
            self._handle_err(message, address)

        elif (opcode == ssftp.OPCODE.ACK.value.get_int()):
            self._handle_ack(message, address)
        elif (opcode == ssftp.OPCODE.DATA.value.get_int()):
            self._handle_data(message, address)

        elif (opcode == ssftp.OPCODE.FIN.value.get_int()):
            self._handle_fin(message, address)

    def _handle_syn(self, msg: bytes, addr: tuple):
        self.logger.info(f"SYN from {addr}")
        self.logger.info(f"Incoming connection from {addr}")
        if addr in self.connections:
            self.logger.info(f"{addr} already in connections. Disregarding.")
            return
        if len(self.connections) >= MAX_CONNECTIONS:
            self.logger.info("Max number of connections reached. Disregarding.")
            return
        # create new connection socket
        conn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn_sock.bind((self.ipv4addr, 0))
        conn_sock.setblocking(False)
        new_connection_thread = Thread(target=lambda: self._listener(addr, conn_sock))
        self._listener_threads[addr] = new_connection_thread
        self._listener_threads[addr].start()
        # add to connections and respond
        self.connections[addr] = {"state": 0, "options": dict(), "socket": conn_sock}
        synack = ssftp.MSG_SYNACK(conn_sock.getsockname()[1])
        conn_sock.sendto(synack.encode(), addr)
        self.logger.info(f"Connected to {addr}")

    # mega function to handle both the DWN and UPL requests
    def _handle_dwn_upl(self, msg: bytes, addr: tuple):
        opcode = int.from_bytes(msg[0:2], 'big')
        if opcode == ssftp.OPCODE.DWN.value.get_int():
            self.logger.info(f"DWN from {addr}")
        elif opcode == ssftp.OPCODE.UPL.value.get_int():
            self.logger.info(f"UPL from {addr}")
        fp = 2  # start where opcode ends
        filepath = ""
        while True:
            curr_char_b = msg[fp]
            fp += 1
            if curr_char_b == 0:
                break
            filepath += chr(curr_char_b)
        filepath = filepath.strip()
        mode = msg[fp]
        fp += 1
        opts = dict()
        while fp < len(msg):
            opt_name = ""
            opt_val = ""
            while True:
                curr_char_b = msg[fp]
                fp+=1
                if curr_char_b == 0:
                    break
                opt_name += chr(curr_char_b)
            while True:
                curr_char_b = msg[fp]
                fp+=1
                if curr_char_b == 0:
                    break
                opt_val += chr(curr_char_b)
            opts[opt_name] = opt_val

        self.logger.info("Parsed options => opdcode: {} filepath: {} | mode: {} | opts: {}".format(opcode, filepath, mode, opts))
        # Get opt values and validate. Clip to max and min values.
        blksize = MAX_BLKSIZE
        timeout = MIN_TIMEOUT_MS
        tsize = None
        if "blksize" in opts:
            try:
                opt_blksize = int(opts["blksize"])
                blksize = min (opt_blksize, MAX_BLKSIZE)
            except ValueError:
                err = ssftp.MSG_ERR(ssftp.ERRCODE.INVALID_OPTIONS, "The blksize option must be a valid integer.")
                self.connections[addr]["socket"].sendto(err.encode(), addr)
                return
        if "timeout" in opts:
            try:
                opt_timeout = int(opts["timeout"])
                timeout = max(MIN_TIMEOUT_MS, min(opt_timeout, MAX_TIMEOUT_MS))
            except ValueError:
                err = ssftp.MSG_ERR(ssftp.ERRCODE.INVALID_OPTIONS, "The timeout option must be a valid integer.")
                self.connections[addr]["socket"].sendto(err.encode(), addr)
                return
        if "tsize" in opts:
            try:
                opt_tsize = int(opts["tsize"])
                tsize = opt_tsize
            except ValueError:
                err = ssftp.MSG_ERR(ssftp.ERRCODE.INVALID_OPTIONS, "The tsize option must be a valid integer.")
                self.connections[addr]["socket"].sendto(err.encode(), addr)
                return

        # getting filename from filepath
        pattern = r"(?<!\\)\/*[^\/]+$"
        filename = re.search(pattern=pattern, string=filepath).group(0).lstrip('/')

        def set_opts():
            # set connection options
            self.connections[addr]["state"] = 1
            self.connections[addr]["options"]["blksize"] = blksize
            self.connections[addr]["options"]["timeout"] = timeout
            self.connections[addr]["options"]["tsize"] = tsize
            self.connections[addr]["options"]["mode"] = mode
            self.connections[addr]["options"]["op"] = opcode
            # Set to 0 when DWN, because we expect an initial ack from client first, and the ack handler will increment it before sending
            initial_block = 0 if opcode == ssftp.OPCODE.DWN.value.get_int() else 1
            self.connections[addr]["options"]["block"] = initial_block
            self.connections[addr]["options"]["filepath"] = filepath
            self.connections[addr]["options"]["filename"] = filename
            self.connections[addr]["options"]["data"] = bytes()
            self.connections[addr]["options"]["terminating_block"] = False
            self.connections[addr]["options"]["pending_ack"] = initial_block + 1  # useless for UPL but still putting it here

            if "sha256sum" in opts:
                self.connections[addr]["options"]["sha256sum"] = opts["sha256sum"]

        if opcode == ssftp.OPCODE.DWN.value.get_int():
            # check if the filepath is STRICTLY only a local filepath
            # immediately deny if the start is a / or . or ..
            # additoinally, ensure that there are no .. ANYWHERE to prevent
            # certain circumventions like dir/../../..
            if filepath.startswith('/') or filepath.startswith('.') or ".." in filepath:
                err = ssftp.MSG_ERR(ssftp.ERRCODE.ACCESS_VIOLATION, "You are not permitted to access that file location.")
                self.connections[addr]["socket"].sendto(err.encode(), addr)
                return
            # check if file exists
            if not os.path.exists(filepath):
                err = ssftp.MSG_ERR(ssftp.ERRCODE.FILE_NOT_FOUND, "File does not exist.")
                self.connections[addr]["socket"].sendto(err.encode(), addr)
                return
            tsize = os.path.getsize(filepath)
            # all is good, send oack
            set_opts()
            with open(filename, "rb") as f:
                digest = hashlib.file_digest(f, "sha256")
            hexdigest = digest.hexdigest()

            self.thread_pool.submit(self._send_oack, addr, tsize, blksize, timeout, sha256sum=hexdigest)
        elif opcode == ssftp.OPCODE.UPL.value.get_int():
            # check if tsize is included
            if "tsize" not in opts:
                err = ssftp.MSG_ERR(ssftp.ERRCODE.INVALID_OPTIONS, "UPL request MUST include tsize option.")
                self.connections[addr]["socket"].sendto(err.encode(), addr)
                return
            # check if file already exists
            # print(self.connections[addr]["options"])
            if os.path.exists(filename):
                err = ssftp.MSG_ERR(ssftp.ERRCODE.FILE_EXISTS, "File to be uploaded already exists.")
                self.logger.info("Cannot fulfill UPL request. File to be uploaded alreadt exists.")
                self.connections[addr]["socket"].sendto(err.encode(), addr)
                return
            # check if disk space is sufficient
            fs = os.statvfs('.')
            block_size = fs.f_frsize
            blocks_free = fs.f_bfree
            free_bytes = block_size * blocks_free
            if tsize > free_bytes:
                err = ssftp.MSG_ERR(ssftp.ERRCODE.DISK_FULL, "UPL request cannot be fulfilled because disk space is insufficient.")
                self.logger.info("Cannot fulfill UPL request. Disk space is insufficient.")
                self.connections[addr]["socket"].sendto(err.encode(), addr)
                return
            # if all is good, send oack
            oack = ssftp.MSG_OACK(tsize=tsize, blksize=blksize, timeout=timeout)
            set_opts()
            self.thread_pool.submit(self._send_oack, addr, tsize, blksize, timeout)

    def _handle_err(self, msg, addr):
        self.logger.info(f"ERR from {addr}")
        err_code = int.from_bytes(msg[2:3], 'big')
        fp = 3
        err_msg = ""
        while True:
            curr_char_b = msg[fp]
            fp += 1

            if curr_char_b == 0:
                break
            err_msg += chr(curr_char_b)
        self.logger.info(f"Received error (code {err_code}) from {addr}. {err_msg}")

    def _handle_data(self, msg, addr):
        seq_num = int.from_bytes(msg[2:4], 'big')
        data = msg[4:-1]  # excluding the final 0 byte
        self.logger.info(f"DATA from {addr} (seq_num={seq_num} len={len(data)})")
        # transaction already ended, these are just stragglers
        if self.connections[addr]["state"] == 0:
            self.logger.info("Transaction already ended. Discarding data")
            return
        if seq_num != self.connections[addr]["options"]["block"]:
            self.logger.info(f"Received out-of-order segment. Expected {self.connections[addr]['options']['block']} Discarding.")
            return
        filename = self.connections[addr]["options"]["filename"]
        with open(filename, 'ab') as f:
            f.write(data)
        # this marks the end of a transaction
        if len(data) < self.connections[addr]["options"]["blksize"]:
            last_ack_num = self.connections[addr]['options']['block'] + 1
            self.connections[addr]["state"] = 0
            self.logger.info("End of file reached!")
            self.thread_pool.submit(self._send_ack, last_ack_num, addr=addr)

            if "sha256sum" in self.connections[addr]["options"]:
                checksum = self.connections[addr]["options"]["sha256sum"]
                with open(filename, "rb") as f:
                    digest = hashlib.file_digest(f, "sha256")
                hexdigest = digest.hexdigest()
                self.logger.info(f"Checksum verification. Digest from client: {checksum}")
                self.logger.info(f"Calculated digest of uploaded file: {hexdigest}")
                if (checksum != hexdigest):
                    self.logger.info(f"File was changed in transmission!")
                else:
                    self.logger.info(f"File is OK.")
            self.connections[addr]["options"] = dict()
        else:
            self.connections[addr]["options"]["block"] += 1
            self.thread_pool.submit(self._send_ack, self.connections[addr]['options']['block'], addr=addr)

    def _handle_ack(self, msg, addr):
        seqnum = int.from_bytes(msg[2:4], 'big')
        self.logger.info(f"ACK from {addr} (seq_num={seqnum})")
        if "block" not in self.connections[addr]['options'] or self.connections[addr]['state'] == 0:
            return
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
            self.logger.info("End of file reached!")
            return
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
            self.logger.info(f"Sending next segment to {addr} (seq_num={opts['block']} len={len(d_send)})")
            self.thread_pool.submit(self._send_data, opts["block"], d_send, addr)

    def _send_data(self, seqnum: int, data: bytes, addr: tuple):
        self.logger.info(f"Sending data to {addr} (seq_num={seqnum} len={len(data)})")
        retries = 0
        timeout = self.connections[addr]["options"]["timeout"]
        while retries <= MAX_RETRIES:
            nextdata = ssftp.MSG_DATA(seq_num=seqnum, data=data)
            if self.drop_packets:
                pass
            else:
                if self.delay_packets: sleep(DEBUG_PACKET_DELAY / 1000)
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

    def _send_ack(self, seqnum: int, addr: tuple):
        self.logger.info(f"Sending ACK to {addr} (seq_num={seqnum})")
        # simply send the last ack
        if self.connections[addr]['state'] == 0:
            nextdata = ssftp.MSG_ACK(seq_num=seqnum)
            self.connections[addr]["socket"].sendto(nextdata.encode(), addr)
            return
        retries = 0
        timeout = self.connections[addr]["options"]["timeout"]
        while retries <= MAX_RETRIES:
            nextdata = ssftp.MSG_ACK(seq_num=seqnum)
            if self.drop_packets:
                pass
            else:
                if self.delay_packets: sleep(DEBUG_PACKET_DELAY / 1000)
                self.connections[addr]["socket"].sendto(nextdata.encode(), addr)
            sleep(timeout/1000)
            block = self.connections[addr]["options"]["block"]
            self.logger.info(seqnum+':', block, seqnum+1)
            if block == seqnum+1:
                break
            retries += 1
            if retries <= MAX_RETRIES:
                self.logger.info(f"No data({seqnum}) received from {addr}. Retrying in {timeout} ms. ({retries}/{MAX_RETRIES})")
        if retries > MAX_RETRIES:
            self.logger.info(f"Max retries reached. Forcefully disconnectiong from {addr}")
            fin = ssftp.MSG_FIN(ssftp.EXITCODE.CONNECTION_LOST)
            self.connections[addr]["socket"].sendto(fin.encode(), addr)
            self.disconnect(addr=addr, exit_code=ssftp.EXITCODE.CONNECTION_LOST)

    def _send_oack(self, addr: tuple, tsize, blksize, timeout, **kwargs):
        self.logger.info(f"Sending OACK to {addr} tsize={tsize} blksize={blksize} timeout={timeout}")
        retries = 0
        oack = ssftp.MSG_OACK(tsize=tsize, blksize=blksize, timeout=timeout, **kwargs)
        while retries <= MAX_RETRIES:
            if self.drop_packets:
                pass
            else:
                if self.delay_packets: sleep(DEBUG_PACKET_DELAY / 1000)
                self.connections[addr]["socket"].sendto(oack.encode(), addr)
            sleep(timeout/1000)
            op = self.connections[addr]["options"]["op"]
            block = self.connections[addr]["options"]["block"]
            pending_ack = self.connections[addr]["options"]["pending_ack"]
            # condition if upl
            if op == ssftp.OPCODE.UPL.value.get_int() and block == 2:
                break
            elif op == ssftp.OPCODE.DWN.value.get_int() and pending_ack == 2:
                break
            retries += 1
            if retries <= MAX_RETRIES:
                self.logger.info(f"No response received from {addr} for OACK. Retrying in {timeout} ms. ({retries}/{MAX_RETRIES})")
        if retries > MAX_RETRIES:
            self.logger.info(f"Max retries reached. Forcefully disconnectiong from {addr}")
            fin = ssftp.MSG_FIN(ssftp.EXITCODE.CONNECTION_LOST)
            self.connections[addr]["socket"].sendto(fin.encode(), addr)
            self.disconnect(addr=addr, exit_code=ssftp.EXITCODE.CONNECTION_LOST)

    def _handle_fin(self, msg, addr):
        exit_code = int.from_bytes(msg[2:4], 'big')
        self.logger.info(f"FIN from {addr} (exit_code={exit_code})")
        # check if connection has an ongoing transaction. If upl, delete the file.
        if self.connections[addr]["state"] == 1:
            if self.connections[addr]["options"]["op"] == ssftp.OPCODE.UPL.value.get_int():
                self.logger.info(f"FIN messsage from {addr} is interrupting an upload. Aborting upload!")
                upl_filename = self.connections[addr]["options"]["filename"]
                if os.path.exists(upl_filename):
                    os.remove(upl_filename)
        # disconnect
        exit_code = int.from_bytes(msg[2:4], 'big')
        finack = ssftp.MSG_FINACK()
        self.connections[addr]["socket"].sendto(finack.encode(), addr)
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

        self.logger.info(f"Listening for new connections @ {self.new_conn_socket.getsockname()}")

    # listens for messages on a specific socket assocaited with a connection
    # used as the target method for new connections.
    # target addr used to check in while loop to ensure the conneciton is
    # still alive
    def _listener(self, target_addr, conn_socket):
        # using the new_conn_socket as a condition
        if self.new_conn_socket is None:
            return False
        while target_addr in self._listener_threads:
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
        self.logger.info(f"Listener for {target_addr} stopped.")

    # Removes the specified address from the connections.
    # Sending of fin/finack message is separate.
    def disconnect(self, addr: tuple, exit_code: ssftp.EXITCODE):
        del self.connections[addr]
        del self._listener_threads[addr]
        self.logger.info(f"Closed connection to {addr} with exit code {exit_code}")


# Test case if run as main. Probably doesn't work right anymore
# because it's all manual setting of values in the server AND client
if __name__ == "__main__":
    ssftpserver = SSFTPServer()

    ssftpserver.new_conn_listen()
    sockname = ssftpserver.new_conn_socket.getsockname()

    while True:
        pass
