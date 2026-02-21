import socket
import ssftp
import os


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
    sock.bind(('192.168.68.70', 30000))

    # messages = {
    #         "syn": ssftp.MSG_SYN(),
    #
    #         "dwn1": ssftp.MSG_DWN('examplefile.png', ssftp.TRANSFER_MODES.netascii, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),
    #         "dwn2": ssftp.MSG_DWN('examplefile.png', ssftp.TRANSFER_MODES.octet, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),
    #
    #         "upl1": ssftp.MSG_UPL('examplefile.png', ssftp.TRANSFER_MODES.netascii, 255, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),
    #         "upl2": ssftp.MSG_UPL('examplefile.png', ssftp.TRANSFER_MODES.octet, 255, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),
    #
    #         "oack": ssftp.MSG_OACK(512, ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT),
    #
    #         "ack": ssftp.MSG_ACK(1),
    #
    #         "data1": ssftp.MSG_DATA(1, 'abcd', ssftp.TRANSFER_MODES.netascii),
    #         "data2": ssftp.MSG_DATA(1, b'\x01\x03\x09', ssftp.TRANSFER_MODES.octet),
    #
    #         "err": ssftp.MSG_ERR(ssftp.ERRCODE.ACCESS_VIOLATION, 'test'),
    #
    #         "fin": ssftp.MSG_FIN(ssftp.EXITCODE.SUCCESS),
    #         "finack": ssftp.MSG_FINACK()
    # }

    # for message_name in messages:
    #     print(f"sending {message_name}...")
    #     sock.sendto(messages[message_name].encode(), ('192.168.68.70', ssftp.SERVER_LISTEN_PORT))

    syn = ssftp.MSG_SYN()
    print(f"sending syn message...")
    sock.sendto(syn.encode(), ('192.168.68.70', ssftp.SERVER_LISTEN_PORT))

    synack = sock.recv(2048)
    newport = int.from_bytes(synack[2:6], 'big')

    upl = ssftp.MSG_UPL('example.out', ssftp.TRANSFER_MODES.octet, os.path.getsize('example.out'), ssftp.DEFAULT_BLKSIZE, ssftp.DEFAULT_TIMEOUT)
    sock.sendto(upl.encode(), ('192.168.68.70', newport))

    oack = sock.recv(2048)
    print(oack)

    # get opts from oack
    opts = dict()
    fp = 2

    while fp < len(oack):
        opt_name = ""
        opt_val = ""

        while True:
            curr_char_b = oack[fp]
            fp+=1

            if curr_char_b == 0:
                break
            opt_name += chr(curr_char_b)

        while True:
            curr_char_b = oack[fp]
            fp+=1

            if curr_char_b == 0:
                break
            opt_val += chr(curr_char_b)

        opts[opt_name] = opt_val

    blksize = int(opts["blksize"])
    timeout = int(opts["timeout"])
    tsize = int(opts["tsize"])

    print("blksize {} timeout {} tsize {} ".format(blksize, timeout, tsize))

    ack1 = ssftp.MSG_ACK(1)
    print("sending ack 1")
    sock.sendto(ack1.encode(), ('192.168.68.70', newport))

    data1 = sock.recv(2048)
    print(data1)

    ack2 = ssftp.MSG_ACK(2)
    print("sending ack 2")
    sock.sendto(ack2.encode(), ('192.168.68.70', newport))

    data2 = sock.recv(2048)
    print(data2)

    ack3 = ssftp.MSG_ACK(3)
    print("sending ack 3")
    sock.sendto(ack3.encode(), ('192.168.68.70', newport))

    data3 = sock.recv(2048)
    print(data3)
    # for message_name in messages: 
    #     if message_name == "syn":
    #         continue
    #     print(f"sending {message_name}...")
    #     sock.sendto(messages[message_name].encode(), ('192.168.68.70', newport))
    #
    #     if "dwn" in message_name or "upl" in message_name:
    #         oack = sock.recv(2048)
    #         print(oack)

    sock.close()

    # sock.send(mystr.encode() + b"0" )
