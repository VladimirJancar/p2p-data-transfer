from datetime import datetime
import queue
import random
import socket
import struct
import threading
from enum import Enum

#!DEBUG
import argparse
import time
#!DEBUG

class State(Enum):
    INPUT = 0
    HANDSHAKE = 1
    CONNECTED = 2
    EXITING = 10

#!DEBUG
# PORT = 8880;PEER_PORT = 8888
# PORT = 8888;PEER_PORT = 8880
PEER_IP = "127.0.0.1"

BUFFER_SIZE = 2048
MAX_FRAGMENT_SIZE = 1400

G_state = State.INPUT
packet_queue = queue.Queue()
handshake_queue = queue.Queue()
#!DEBUG


class PacketData():

    def __init__(self):
        pass

    def createPacket(self, data, ack_num: int, seq_num: int, ack=0, syn=0, fin=0, ctr=0) -> bytes:
        flags = (ack << 7) | (syn << 6) | (fin << 5) | (ctr << 4) #!| (self.sfs << 3) | (self.lfg << 2) | (self.ftr << 1)
        checksum = 0 #self.calculateChecksum(data.encode('utf-8'))

        # if (self.ftr==1 and self.seq_num==2 and CORRUPT):
        #     checksum = 0
        #     CORRUPT = False

        header = struct.pack(
            '!IIBH',#! SIZE
            ack_num,          # 32b
            seq_num,          # 32b
            flags,            # 8b
            checksum,         # 16b
        )
        #TODO checksum header+payload 
        return header + data.encode('utf-8')

    def parsePacket(self, packet: bytes):
        header = packet[:11]
        ack_num, seq_num, flags, checksum = struct.unpack('!IIBH', header)
        data = packet[11:].decode('utf-8') #! 11:
        ack=(flags >> 7) & 1
        syn=(flags >> 6) & 1
        fin=(flags >> 5) & 1
        ctr=(flags >> 4) & 1
        # sfs=(flags >> 3) & 1
        # lfg=(flags >> 2) & 1
        # ftr=(flags >> 1) & 1

        return (ack_num, seq_num, ack, syn, fin, ctr, checksum, data)
    
    def calculateChecksum(self, data: bytes):
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


class Connection():
    fragment_size = MAX_FRAGMENT_SIZE

    sock = None
    src_ip = None
    src_port = None
    peer_ip = None 
    peer_port = None

    pd = PacketData()

    def __init__(self, src_ip, src_port, peer_ip, peer_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.src_ip = src_ip
        self.src_port = src_port
        self.peer_ip = peer_ip
        self.peer_port = peer_port

        threading.Thread(target=receive, args=(self.sock, src_ip, src_port), daemon=True).start()

    def handshake(self):
        global G_state
        my_seq = random.randint(0, 10000)

        syn_sent = False
        syn_ack_sent = False

        printHandshakeInfo("Starting...")

        while True:
            self.sendPacket(self.pd.createPacket('', 0, my_seq, 0, 1))
            printHandshakeInfo("SYN packet sent...")
            syn_sent = True
            try:
                packet = handshake_queue.get(timeout=5)  # Blocks until packet arrives
                #handle_packet(parsed)
            except queue.Empty:
                printHandshakeInfo("No reply to SYN packet...")
                continue

            #TODO ack numbering
            ack_num = packet[0]
            seq_num = packet[1]
            ack = packet[2]
            syn = packet[3]

            if syn_sent and syn and ack:
                my_seq += 1
                printHandshakeInfo("SYN-ACK packet received...")
                printHandshakeInfo("Sending ACK packet...")
                self.sendPacket(self.pd.createPacket('', ack_num=seq_num + 1, seq_num=my_seq, ack=1))
                printHandshakeInfo("Connected.")
                G_state = State.CONNECTED
                break

            elif syn:
                printHandshakeInfo("SYN packet received...")
                printHandshakeInfo("Sending SYN-ACK packet...")
                self.sendPacket(self.pd.createPacket('', 0, my_seq, 1, 1))
                syn_ack_sent = True

            elif syn_ack_sent and ack:
                printHandshakeInfo("SYN-ACK packet received...")
                printHandshakeInfo("Connected.")
                G_state = State.CONNECTED
                break
        print()

    def sendPacket(self, packet: bytes):
        self.sock.sendto(packet, (self.peer_ip, self.peer_port))
        #TODO fragmentation and ack storage

    def end(self):
        pass

    def heartbeat(self):
        pass
        

def main():
    #!DEBUG 
    parser = argparse.ArgumentParser(description="P2P Communicator")
    parser.add_argument('--selfport', type=int, required=True, help="Port number to use")
    parser.add_argument('--peerport', type=int, required=True, help="Port number of peer")
    args = parser.parse_args()

    src_port = args.selfport
    peer_port = args.peerport
    #!DEBUG


    global G_state
    src_ip = PEER_IP
    peer_ip = PEER_IP #input("[INPUT] peer IP address: ").strip()
    #!src_port = PORT #int(input("[INPUT] listening port: ").strip())
    #!peer_port =  PEER_PORT #int(input("[INPUT] peer port: ").strip())

    connection = Connection(src_ip, src_port, peer_ip, peer_port)

    G_state = State.HANDSHAKE
    connection.handshake()
    
    while True:
        if (G_state == State.CONNECTED):
            handleInput(connection.sock, peer_ip, peer_port)


def receive(sock, src_ip, src_port):
    global G_state

    pd = PacketData()
    sock.bind((src_ip, src_port))

    while G_state != State.EXITING:
        try:
            packet, addr = sock.recvfrom(BUFFER_SIZE)
            bytes = pd.parsePacket(packet)
            if (G_state == State.HANDSHAKE):
                handshake_queue.put(bytes)
            else:
                #packet_queue.put(bytes)
                printTextMessages(addr, bytes)
        except Exception as e:
            #print("Receiver error:", e)
            pass


def handleInput(sock, peer_ip, peer_port):
    user_input = input()

    #TODO
    # if user_input.startswith("/setfragsize "):
    #     try:
    #         new_size = int(user_input.split()[1])
    #         self.setFragmentSize(new_size)
    #     except ValueError:
    #         print("Invalid command. Usage: /setfragsize <size>")
    # elif user_input.startswith("/send "):
    #     file_path = user_input[6:].strip()
    #     self.sendFile(file_path)
    # elif user_input.startswith("/disconnect"):
    #     self.trerminateConnection()
    # else:
    pd = PacketData()
    packet = pd.createPacket(user_input, 0, 0)
    sock.sendto(packet, (peer_ip, peer_port))

def printTextMessages(addr, bytes):
    print(f"({datetime.now().strftime("%H:%M")}) {addr[0]}:{addr[1]} >> {bytes[7]}") #TODO ADD TIME


def printHandshakeInfo(message):
    print(f"({datetime.now().strftime("%H:%M")}) [HANDSHAKE]: {message}")

if __name__ == "__main__":
    main()
    




    
# def sendText(self, message):
#         self.message_seq_num = self.message_seq_num + 1
#         if self.message_seq_num == 0: 
#             self.message_seq_num = 1

#         if message == "": return

#         if len(message) > protocol.frag_size:
#             fgs = protocol.fragmentData(message)
#             frags = enumerate(fgs)
#             for seq_num, fragment in frags:
#                 if seq_num == len(fgs)-1:
#                     packet = Packet(seq_num=self.message_seq_num, data=fragment, ftr=1, lfg=1)
#                 else:
#                     packet = Packet(seq_num=self.message_seq_num, data=fragment, ftr=1)

#                 self.socket.sendto(packet.toBytes(), (self.dest_ip, self.dest_port))
#                 self.message_seq_num += 1
                
#         else:
#             packet = Packet(seq_num=self.message_seq_num, data=message)
#             self.socket.sendto(packet.toBytes(), (self.dest_ip, self.dest_port))
#             self.message_seq_num += 1

