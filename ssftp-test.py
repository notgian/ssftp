import socket
import ssftp


# def get_my_ip():
#     """Attempts to get the local network IP. Falls back to localhost."""
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     try:
#         s.connect(('10.255.255.255', 1))
#         IP = s.getsockname()[0]
#     except Exception:
#         # Fallback to localhost
#         IP = '127.0.0.1'
#     finally:
#         s.close()
#     return IP


if __name__ == "__main__":

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.bind(('', 30000))

    messages = {

            "syn": ssftp.MSG_SYN(),

            "synack": ssftp.MSG_SYNACK(6767),

            "dwn1": ssftp.MSG_DWN('examplefile.png', ssftp.TRANSFER_MODES.netascii, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),
            "dwn2": ssftp.MSG_DWN('examplefile.png', ssftp.TRANSFER_MODES.octet, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),

            "upl1": ssftp.MSG_UPL('examplefile.png', ssftp.TRANSFER_MODES.netascii, 255, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),
            "upl2": ssftp.MSG_UPL('examplefile.png', ssftp.TRANSFER_MODES.octet, 255, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),

            "oack": ssftp.MSG_OACK(512, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),

            "ack": ssftp.MSG_ACK(1),

            "data1": ssftp.MSG_DATA(1, 'abcd', ssftp.TRANSFER_MODES.netascii),
            "data2": ssftp.MSG_DATA(1, b'\x01\x03\x09', ssftp.TRANSFER_MODES.octet),

            "err": ssftp.MSG_ERR(ssftp.ERRCODE.ACCESS_VIOLATION, 'test'),

            "fin": ssftp.MSG_FIN(ssftp.EXITCODE.SUCCESS),
            "finack": ssftp.MSG_FINACK()
    }

    for message_name in messages:
        print(f"sending {message_name}...")
        sock.sendto(messages[message_name].encode(), ('127.0.0.1', ssftp.SERVER_LISTEN_PORT))

    sock.close()

    # sock.send(mystr.encode() + b"0" )
