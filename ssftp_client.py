import socket
import ssftp
from threading import Thread
from time import sleep

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

CLIENT_BLKSIZE = 512
CLIENT_TIMEOUT = 500

MAX_TIMEOUT_MS = 3000
MIN_TIMEOUT_MS = 200

ENABLE_LOGGING = True

DEBUG_PACKET_DELAY = 3000


class SSFTPClient():
    def __init__(self, logger_stream=sys.stdout):
        # dict of connection containing states and options
        # two possible states: 0 - idle, 1 - smth's happening aka data transfer
        # {addr: server_address, state: 0|1,  options: {opts:here,} }
        self.connection = {
                'addr': None,
                'state': None,  # 0 | 1
                'options': {}
        }

        self.socket = socket.socket(type=socket.AF_INET, family=socket.SOCK_DGRAM)
        self.socket.bind(('', 0))
        self.socket.setblocking(False)
        self.portnum = self.socket.getsockname()[1]

        self._listener_thread = None

        # This option is only for testing. Drop packets takes precedence.
        self.drop_packets = False
        self.delay_packets = False

        handler = logging.StreamHandler(logger_stream)
        handler.setLevel(logging.INFO)
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)
        self.logger.disabled = False

        # This exit handler will allow us to send a fin to the server
        # before dying in the case a SIGINT is sent to the program
        def exit_handler(signum, frame):
            if self.connection['addr'] is not None:
                addr = self.connection['addr']
                self.logger.info(f"Forceful termination of program. Disconnecting from {addr}")
                exitcode = ssftp.EXITCODE.FORCEFUL_TERMINATION
                fin = ssftp.MSG_FIN(exitcode)
                self.socket.sendto(fin.encode(), addr)
                self.disconnect(exit_code=exitcode)
            exit(0)
        signal.signal(signal.SIGINT, exit_handler)
        self.logger.info(f"Started SSFTP client @ {self.socket.getsockname()}")

    def kill(self):
        signal.raise_signal(signal.SIGINT)

    # =======================
    # MESSAGE HANDLING
    # =======================

    def _message_mux(self, message: bytes, address: tuple):
        opcode_bytes = message[0:2]
        opcode = int.from_bytes(opcode_bytes, 'big')

        # server should be SENDING, not receiving a SYNACK
        if (opcode == ssftp.OPCODE.SYNACK.value.get_int()):
            self._handle_synack(message, address)
            return

        # the following operations require an existing connection
        if self.connection['addr'] is None:
            self.logger.info(f"No existing connection. Disregarding message from {address}.")
            return
        elif self.connection['addr'] != address:
            self.logger.info(f"Received message from {address} who is not the server. Disregarding.")
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
        self.logger.info(f"SYNACK from {addr}")

        if self.connection['addr'] == addr:
            self.logger.info(f"Already connected to {addr}. Disregarding.")
            return
        elif self.connection['addr'] is not None:
            self.logger.info(f"Already connected to a server. Disregarding {addr}.")
            return

        ipaddr = addr[0]
        newport = int.from_bytes(msg[2:6], 'big')
        newaddr = (ipaddr, newport)
        # add to connections and start listening
        self.connection['addr'] = newaddr
        self.connection['state'] = 0
        self.connection['options']: dict()
        connection_thread = Thread(target=lambda: self._listener(newaddr), daemon=True)
        self._listener_thread = connection_thread
        self._listener_thread.start()
        self.logger.info(f"Connected to server {newaddr}")

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

    def _handle_oack(self, msg, addr):
        self.logger.info(f"OACK from {addr}")
        if self.connection["state"] == 1:
            self.logger.info("Already in transfer. Disregarding OACK")
            return
        # parse options
        fp = 2  # start where opcode ends

        opts = dict()
        while fp < len(msg):
            opt_name = ""
            opt_val = ""
            while True:
                curr_char_b = msg[fp]
                fp += 1
                if curr_char_b == 0:
                    break
                opt_name += chr(curr_char_b)
            while True:
                curr_char_b = msg[fp]
                fp += 1
                if curr_char_b == 0:
                    break
                opt_val += chr(curr_char_b)
            opts[opt_name] = opt_val

        blksize = MAX_BLKSIZE
        timeout = MIN_TIMEOUT_MS
        tsize = None

        if "blksize" in opts:
            try:
                opt_blksize = int(opts["blksize"])
                blksize = min(opt_blksize, MAX_BLKSIZE)
            except ValueError:
                err = ssftp.MSG_ERR(ssftp.ERRCODE.INVALID_OPTIONS, "The blksize option must be a valid integer.")
                self.socket.sendto(err.encode(), addr)
                return
        if "timeout" in opts:
            try:
                opt_timeout = int(opts["timeout"])
                timeout = max(MIN_TIMEOUT_MS, min(opt_timeout, MAX_TIMEOUT_MS))
            except ValueError:
                err = ssftp.MSG_ERR(ssftp.ERRCODE.INVALID_OPTIONS, "The timeout option must be a valid integer.")
                self.socket.sendto(err.encode(), addr)
                return
        if "tsize" in opts:
            try:
                opt_tsize = int(opts["tsize"])
                tsize = opt_tsize
            except ValueError:
                err = ssftp.MSG_ERR(ssftp.ERRCODE.INVALID_OPTIONS, "The tsize option must be a valid integer.")
                self.socket.sendto(err.encode(), addr)
                return

        self.logger.info(f"OACK options set: blksize={blksize} timeout={timeout} tsize={tsize}")

        mode = self.connection['temp_opts']['mode']
        opcode = self.connection['temp_opts']['op']
        filepath = self.connection['temp_opts']['filepath']
        # getting filename from filepath
        pattern = r"(?<!\\)\/*[^\/]+$"
        filename = re.search(pattern=pattern, string=filepath).group(0).lstrip('/')

        # set connection options
        self.connection["state"] = 1
        self.connection["options"]["blksize"] = blksize
        self.connection["options"]["timeout"] = timeout
        self.connection["options"]["tsize"] = tsize
        self.connection["options"]["mode"] = mode
        self.connection["options"]["op"] = opcode
        # Set to 1 when DWN, because client sends an initial ack first, and the ack handler will in
        initial_block = 1
        self.connection["options"]["block"] = initial_block
        self.connection["options"]["filepath"] = filepath
        self.connection["options"]["filename"] = filename
        self.connection["options"]["data"] = bytes()
        self.connection["options"]["terminating_block"] = False
        self.connection["options"]["pending_ack"] = initial_block + 1  # useless for UPL but still putting it here

        # send an ack to receive block 1
        if opcode == ssftp.OPCODE.DWN.value.get_int():
            self.logger.info(f"Sending ack to {self.connection['addr']} to receive first block.")
            Thread(target=lambda: self._send_ack(1, self.connection['addr'])).start()
        elif opcode == ssftp.OPCODE.UPL.value.get_int():
            opts = self.connection["options"]
            d_start = (opts["block"]-1) * opts["blksize"]
            f = open(opts["filepath"], 'rb')
            f.seek(d_start)
            d_send = f.read(opts["blksize"])
            self.logger.info(f"Sending first segment to {addr} (seq_num={opts['block']} len={len(d_send)})")
            Thread(target=lambda: self._send_data(opts["block"], d_send, addr)).start()

    def _handle_data(self, msg, addr):
        seq_num = int.from_bytes(msg[2:4], 'big')
        data = msg[4:-1]  # excluding the final 0 byte
        self.logger.info(f"DATA from {addr} (seq_num={seq_num} len={len(data)})")
        if seq_num != self.connection["options"]["block"]:
            self.logger.info(f"Received out-of-order segment. Expected {self.connection['options']['block']} Discarding.")
            return

        filename = self.connection["options"]["filename"]
        filename_temp = filename + '.tmp'
        with open(filename_temp, 'ab') as f:
            f.write(data)

        # this marks the end of a transaction
        if len(data) < self.connection["options"]["blksize"]:
            last_ack_num = self.connection['options']['block'] + 1
            self.connection["state"] = 0
            self.connection["options"] = dict()
            self.logger.info("End of file reached!")
            Thread(target=lambda: self._send_ack(last_ack_num, self.connection['addr'])).start()
            if os.path.exists(filename) and os.path.isfile(filename):
                os.remove(filename)
            os.rename(filename_temp, filename)
        else:
            self.connection["options"]["block"] += 1
            Thread(target=lambda: self._send_ack(self.connection['options']['block'], self.connection['addr'])).start()

    def _handle_ack(self, msg, addr):
        seqnum = int.from_bytes(msg[2:4], 'big')
        self.logger.info(f"ACK from {addr} (seq_num={seqnum})")
        # discard out-of-order segment
        if self.connection["options"]["block"] != seqnum-1:
            self.logger.info(f"Received out-of-order segment (seqnum={seqnum}) from {addr}. Discarding.")
            return
        self.connection["options"]["pending_ack"] += 1

        # check if last block sent was a terminating block and reset state
        # this marks the end of a transaction
        if self.connection["options"]["terminating_block"]:
            self.connection["state"] = 0
            self.connection["options"] = dict()
            self.logger.info("End of file reached!")
            return
        # send next segment
        else:
            opts = self.connection["options"]
            opts["block"] += 1
            d_start = (opts["block"]-1) * opts["blksize"]
            f = open(opts["filepath"], 'rb')
            f.seek(d_start)
            d_send = f.read(opts["blksize"])
            # determine if current segment is terminating
            if len(d_send) < opts["blksize"]:
                opts["terminating_block"] = True
            Thread(target=lambda: self._send_data(opts["block"], d_send, addr)).start()

    def _send_data(self, seqnum: int, data: bytes, addr: tuple):
        self.logger.info(f"Sending data to {addr} (seq_num={seqnum} len={len(data)})")
        retries = 0
        timeout = self.connection["options"]["timeout"]

        while retries <= MAX_RETRIES:
            nextdata = ssftp.MSG_DATA(seq_num=seqnum, data=data)
            if "pending_ack" not in self.connection["options"]:
                if self.connection["state"] == 0:
                    break
                continue
            pending_ack = self.connection["options"]["pending_ack"]
            if self.drop_packets:
                pass
            else:
                if self.delay_packets: sleep(DEBUG_PACKET_DELAY / 1000)
                self.socket.sendto(nextdata.encode(), addr)
            if seqnum+1 < pending_ack:
                break
            retries += 1
            if retries <= MAX_RETRIES:
                self.logger.info(f"No ack({seqnum+1}) received from {addr}. Retrying in {timeout} ms. ({retries}/{MAX_RETRIES})")
            sleep(timeout/1000)
        if retries > MAX_RETRIES:
            self.logger.info(f"Max retries reached. Forcefully disconnectiong from {addr}")
            fin = ssftp.MSG_FIN(ssftp.EXITCODE.CONNECTION_LOST)
            self.socket.sendto(fin.encode(), addr)
            self.disconnect(exit_code=ssftp.EXITCODE.CONNECTION_LOST)

    def _send_ack(self, seqnum: int, addr: tuple):
        self.logger.info(f"Sending ACK to {addr} (seq_num={seqnum})")

        # simply send the last ack
        if self.connection['state'] == 0:
            nextdata = ssftp.MSG_ACK(seq_num=seqnum)
            self.socket.sendto(nextdata.encode(), addr)
            return

        retries = 0
        timeout = self.connection["options"]["timeout"]
        while retries <= MAX_RETRIES:
            nextdata = ssftp.MSG_ACK(seq_num=seqnum)
            if self.drop_packets:
                pass
            else:
                if self.delay_packets: sleep(DEBUG_PACKET_DELAY / 1000)
                self.socket.sendto(nextdata.encode(), addr)
            if "block" not in self.connection["options"]:
                if self.connection["state"] == 0:
                    break
                continue
            block = self.connection["options"]["block"]
            if block == seqnum+1:
                break
            retries += 1
            if retries <= MAX_RETRIES:
                self.logger.info(f"No data({seqnum}) received from {addr}. Retrying in {timeout} ms. ({retries}/{MAX_RETRIES})")
            sleep(timeout/1000)
        if retries > MAX_RETRIES:
            self.logger.info(f"Max retries reached. Forcefully disconnectiong from {addr}")
            fin = ssftp.MSG_FIN(ssftp.EXITCODE.CONNECTION_LOST)
            self.socket.sendto(fin.encode(), addr)
            self.disconnect(exit_code=ssftp.EXITCODE.CONNECTION_LOST)

    def _handle_fin(self, msg, addr):
        self.logger.info(f"FIN from {addr}")
        # check if connection has an ongoing transaction. If dwn, delete the file.
        if self.connection["state"] == 1:
            if self.connection["options"]["op"] == ssftp.OPCODE.DWN.value.get_int():
                self.logger.info("FIN messsage from {addr} is interrupting a download. Aborting download!")
                dwn_filename = self.connection["options"]["filename"] + '.tmp'
                if os.path.exists(dwn_filename):
                    os.remove(dwn_filename)
                self.disconnect(ssftp.EXITCODE.CONNECTION_LOST)
        # disconnect
        exit_code = int.from_bytes(msg[2:4], 'big')
        self.disconnect(exit_code=exit_code)

    def _handle_finack(self, msg, addr):
        pass

    # =========================
    # Listener Functions
    # =========================

    def _listener(self, target_addr):
        if self.connection['addr'] is None:
            return False
        while self.connection['addr'] is not None:
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

    # =======================
    #    Client operations
    # =======================

    def connect_to(self, addr: tuple):
        if self.connection['addr'] is not None:
            self.logger.info(f"Connect failed! Already connected to {addr}.")
            return

        syn = ssftp.MSG_SYN()
        self.socket.sendto(syn.encode(), addr)

        # wait for synack
        self.logger.info(f"Attempting to connect to server @ {addr}.")
        retries = 0
        while retries < MAX_RETRIES and self.connection['addr'] is None:
            try:
                data, retaddr = self.socket.recvfrom(MAX_MESSAGE_LENGTH)
                opcode = int.from_bytes(data[:2], 'big')
                # skip non synack messages
                if opcode != ssftp.OPCODE.SYNACK.value.get_int():
                    continue
                self._message_mux(data, addr)
                if MESSAGE_READ_INTERVAL_MS > 0:
                    sleep(MESSAGE_READ_INTERVAL_MS/1000)
            except socket.error:
                if MESSAGE_TIMEOUT_MS > 0:
                    sleep(MESSAGE_TIMEOUT_MS/1000)
                    retries += 1

        if self.connection['addr'] is None:
            self.logger.info(f"Failed to connect to {addr}.")

    def send_dwn(self, filepath: str, transfer_mode: ssftp.TRANSFER_MODES):
        dwn = ssftp.MSG_DWN(
                filepath=filepath,
                mode=transfer_mode,
                blksize=CLIENT_BLKSIZE,
                timeout=CLIENT_TIMEOUT
        )
        self.connection['temp_opts'] = {
            'filepath': filepath,
            'mode': transfer_mode,
            'op': ssftp.OPCODE.DWN.value.get_int(),
        }
        self.logger.info(f"Sending DWN request to {self.connection['addr']}")
        self.socket.sendto(dwn.encode(), self.connection['addr'])

    # This method does not account for file
    # existing or not existing. Please ensure to
    # check this is creating the operations for the client.
    def send_upl(self, filepath: str, transfer_mode: ssftp.TRANSFER_MODES):
        upl = ssftp.MSG_UPL(
                filepath=filepath,
                mode=transfer_mode,
                blksize=CLIENT_BLKSIZE,
                timeout=CLIENT_TIMEOUT,
                tsize=os.path.getsize(filepath)
        )
        self.connection['temp_opts'] = {
            'filepath': filepath,
            'mode': transfer_mode,
            'op': ssftp.OPCODE.UPL.value.get_int(),
        }
        self.logger.info(f"Sending UPL request to {self.connection['addr']}")
        self.socket.sendto(upl.encode(), self.connection['addr'])

    def disconnect(self, exit_code: ssftp.EXITCODE):
        server_addr = self.connection['addr']
        self.connection['addr'] = None
        self.connection['state'] = None
        self.connection['options'] = dict()
        self._listener_thread = None
        self.logger.info(f"Closed connection to server {server_addr} with exit code {exit_code}")


# old test case for client. May not work anymore
# due to this having been manually configured w/o
# application boundaries
if __name__ == "__main__":
    known_server = ('192.168.68.70', ssftp.SERVER_LISTEN_PORT)
    ssftpclient = SSFTPClient()

    ssftpclient.connect_to(known_server)

    while ssftpclient.connection['addr'] is None:
        pass

    # ssftpclient.send_upl('example.out', ssftp.TRANSFER_MODES.octet)
    ssftpclient.send_dwn('example.out', ssftp.TRANSFER_MODES.octet)

    while True:
        pass
