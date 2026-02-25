from enum import Enum


class _INT_VALUE():
    def __init__(self, value: int):
        self.value: int = value

    def get_int(self):
        return self.value

    def get_bytes(self):
        return self.value.to_bytes(2, 'big')


class OPCODE(Enum):
    SYN = _INT_VALUE(1)
    SYNACK = _INT_VALUE(2)
    DWN = _INT_VALUE(3)
    UPL = _INT_VALUE(4)
    OACK = _INT_VALUE(5)
    ERR = _INT_VALUE(6)
    ACK = _INT_VALUE(7)
    DATA = _INT_VALUE(8)
    FIN = _INT_VALUE(9)
    FINACK = _INT_VALUE(10)


class TRANSFER_MODES(Enum):
    octet = 1
    netascii = 2


DEFAULT_BLKSIZE = 512
DEFAULT_TIMEOUT = 500  # in milliseconds


class ERRCODE(Enum):
    NOT_DEFINED = _INT_VALUE(0)
    FILE_NOT_FOUND = _INT_VALUE(1)
    ACCESS_VIOLATION = _INT_VALUE(2)
    FILE_EXISTS = _INT_VALUE(3)
    DISK_FULL = _INT_VALUE(4)
    INVALID_OPTIONS = _INT_VALUE(5)
    ILLEGAL_OPERATION = _INT_VALUE(6)


class EXITCODE(Enum):
    SUCCESS = _INT_VALUE(0)
    FORCEFUL_TERMINATION = _INT_VALUE(1)
    CONNECTION_LOST = _INT_VALUE(2)
    CRITICAL_ERROR = _INT_VALUE(255)


SERVER_LISTEN_PORT = 3900


class Message():
    def __init__(self):
        pass

    def encode():
        raise Exception("This message must be overwritten by the specific message type.")


class MSG_SYN(Message):
    def encode(self):
        return OPCODE.SYN.value.get_bytes() + b'\x00'


class MSG_SYNACK(Message):
    def __init__(self, port_number: int):
        self.port_number = port_number

    def encode(self):
        return OPCODE.SYNACK.value.get_bytes() + self.port_number.to_bytes(4, 'big') + b'\x00'


class MSG_DWN(Message):
    def __init__(self, filepath: str, mode: TRANSFER_MODES, blksize=DEFAULT_BLKSIZE, timeout=DEFAULT_TIMEOUT):
        self.filepath = filepath
        self.mode = mode

        self.blksize: int = blksize
        self.timeout: int = timeout

    def encode(self):
        message = OPCODE.DWN.value.get_bytes() + self.filepath.encode('ascii') + b'\x00'
        message += self.mode.value.to_bytes(1, 'big')

        if self.blksize is None and self.timeout is None:
            message += b'\x00'
            return message

        if self.blksize is not None:
            message += 'blksize'.encode('ascii') + b'\x00' + str(self.blksize).encode('ascii') + b'\x00'
        if self.timeout is not None:
            message += 'timeout'.encode('ascii') + b'\x00' + str(self.timeout).encode('ascii') + b'\x00'
        return message


class MSG_UPL(Message):
    def __init__(self, filepath: str, mode: TRANSFER_MODES, tsize: int, blksize=DEFAULT_BLKSIZE, timeout=DEFAULT_TIMEOUT, **kwargs):
        self.filepath = filepath
        self.mode = mode

        self.tsize: int = tsize
        self.blksize: int = blksize
        self.timeout: int = timeout
        self.otherOpts = dict(kwargs)

    def encode(self):
        message = OPCODE.UPL.value.get_bytes() + self.filepath.encode('ascii') + b'\x00'
        message += self.mode.value.to_bytes(1, 'big')

        message += 'tsize'.encode('ascii') + b'\x00' + str(self.tsize).encode('ascii') + b'\x00'

        if self.blksize is not None:
            message += 'blksize'.encode('ascii') + b'\x00' + str(self.blksize).encode('ascii') + b'\x00'
        if self.timeout is not None:
            message += 'timeout'.encode('ascii') + b'\x00' + str(self.timeout).encode('ascii') + b'\x00'

        for optName in self.otherOpts.keys():
            message += optName.encode('ascii') + b'\x00' + str(self.otherOpts[optName]).encode('ascii') + b'\x00'
        return message


class MSG_OACK(Message):
    def __init__(self, tsize: int, blksize=DEFAULT_BLKSIZE, timeout=DEFAULT_TIMEOUT, **kwargs):
        self.tsize: int = tsize
        self.blksize: int = blksize
        self.timeout: int = timeout
        self.otherOpts = dict(kwargs)

    def encode(self):
        message = OPCODE.OACK.value.get_bytes()

        message += 'blksize'.encode('ascii') + b'\x00' + str(self.blksize).encode('ascii') + b'\x00'
        message += 'tsize'.encode('ascii') + b'\x00' + str(self.tsize).encode('ascii') + b'\x00'
        message += 'timeout'.encode('ascii') + b'\x00' + str(self.timeout).encode('ascii') + b'\x00'
        for optName in self.otherOpts.keys():
            message += optName.encode('ascii') + b'\x00' + str(self.otherOpts[optName]).encode('ascii') + b'\x00'

        return message


class MSG_ERR(Message):
    def __init__(self, err_code: ERRCODE, message_str: str):
        self.err_code = err_code
        self.message_str = message_str

    def encode(self):
        return OPCODE.ERR.value.get_bytes() + self.err_code.value.get_bytes() + self.message_str.encode('ascii') + b'\x00'


class MSG_ACK(Message):
    def __init__(self, seq_num: int):
        self.seq_num = seq_num

    def encode(self):
        return OPCODE.ACK.value.get_bytes() + self.seq_num.to_bytes(2, 'big') + b'\x00'


class MSG_DATA(Message):
    def __init__(self, seq_num: int, data: bytes | str):
        self.seq_num = seq_num
        self.data = data

    def encode(self):
        return OPCODE.DATA.value.get_bytes() + self.seq_num.to_bytes(2, 'big') + self.data + b'\x00'


class MSG_FIN(Message):
    def __init__(self, exit_code: EXITCODE):
        self.exit_code = exit_code

    def encode(self):
        return OPCODE.FIN.value.get_bytes() + self.exit_code.value.get_bytes() + b'\x00'


class MSG_FINACK(Message):
    def encode(self):
        return OPCODE.FINACK.value.get_bytes() + b'\x00'
