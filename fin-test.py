import socket
import ssftp
import os
import time

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

    syn = ssftp.MSG_SYN()
    print(f"sending syn message...")
    sock.sendto(syn.encode(), ('192.168.68.70', ssftp.SERVER_LISTEN_PORT))

    synack = sock.recv(2048)
    newport = int.from_bytes(synack[2:6], 'big')
    time.sleep(0.1)

    # this should fail
    sock.sendto(syn.encode(), ('192.168.68.70', ssftp.SERVER_LISTEN_PORT))
    time.sleep(0.1)

    fin = ssftp.MSG_FIN(ssftp.EXITCODE.SUCCESS)
    # should fail
    sock.sendto(fin.encode(), ('192.168.68.70', ssftp.SERVER_LISTEN_PORT))
    time.sleep(0.1)

    # should disconnect
    sock.sendto(fin.encode(), ('192.168.68.70', newport))
    sock.close()
