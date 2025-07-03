import socket
import struct
import threading
from enum import Enum


# PORT = 8880;PEER_PORT = 8888
PORT = 8888;PEER_PORT = 8880

PEER_IP = "127.0.0.1"
BUFFER_SIZE = 1024
MAX_FRAGMENT_SIZE = 1400


class State(Enum):
    INPUT = 0
    HANDSHAKE = 1
    CONNECTED = 2


class Communication():
    fragment_size = MAX_FRAGMENT_SIZE

    def __init__(self):
        pass

    def endConnection():
        pass

    def heartbeat():
        pass
        

class Data():

    def __init__(self):
        pass

    def encodePacket(self, data):
        flags = (self.ack << 7) | (self.syn << 6) | (self.fin << 5) | (self.err << 4) | (self.sfs << 3) | (self.lfg << 2) | (self.ftr << 1)
        checksum = self.calculateChecksum(data.encode('utf-8'))

        if (self.ftr==1 and self.seq_num==2 and CORRUPT):
            checksum = 0
            CORRUPT = False

        header = struct.pack(
            '!IIBH',
            self.ack_num,          # 32b
            self.seq_num,          # 32b
            flags,                 # 8b
            checksum,              # 16b
        )
        return header + data.encode('utf-8')

    def decodePacket(self, packet):
        header = packet[:11]
        ack_num, seq_num, flags, checksum = struct.unpack('!IIBH', header)
        data = packet[11:].decode('utf-8')
        return Packet(
            ack_num=ack_num,
            seq_num=seq_num,
            ack=(flags >> 7) & 1,
            syn=(flags >> 6) & 1,
            fin=(flags >> 5) & 1,
            err=(flags >> 4) & 1,
            sfs=(flags >> 3) & 1,
            lfg=(flags >> 2) & 1,
            ftr=(flags >> 1) & 1,
            checksum=checksum,
            data=data
        )

    def calculateChecksum(self, data):
        polynomial = 0x8005
        crc = 0xFFFF

        for byte in data:
            crc ^= (byte << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ polynomial
                else:
                    crc <<= 1
                crc &= 0xFFFF

        crc ^= 0xFFFF
        return crc


def main():
    state = State.INPUT
    src_ip = PEER_IP
    peer_ip = PEER_IP #input("[INPUT] peer IP address: ").strip()
    src_port = PORT #int(input("[INPUT] listening port: ").strip())
    peer_port =  PEER_PORT #int(input("[INPUT] peer port: ").strip())

    #TODO separate
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    threading.Thread(target=receive, args=(src_ip, src_port), daemon=True).start()

    #state = State.HANDSHAKE
    #TODO handshake

    state = State.CONNECTED
    
    while True:
        if (state == State.CONNECTED):
            sender(sock, peer_ip, peer_port)


def receive(sock, src_ip, src_port):
    sock.bind((src_ip, src_port))

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        print(f"{addr[0]}:{addr[1]} >> {data.decode()}")


def sender(sock, peer_ip, peer_port):
    msg = input("\n")
    sock.sendto(msg.encode(), (peer_ip, peer_port))


if __name__ == "__main__":
    main()
    