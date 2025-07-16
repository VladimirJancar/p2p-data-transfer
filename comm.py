import os
import queue
import random
import socket
import struct
import threading
import numpy as np
from enum import Enum
from datetime import datetime
import time

#!DEBUG
import argparse
#!DEBUG

class State(Enum):
    INPUT = 0
    HANDSHAKE = 1
    CONNECTED = 2
    FILE_TRANSFER = 3
    FILE_RECEIVE = 4
    EXITING = 10

#!DEBUG
# PORT = 8880;PEER_PORT = 8888
# PORT = 8888;PEER_PORT = 8880
PEER_IP = "127.0.0.1"
#!DEBUG
BUFFER_SIZE = 2048
MAX_FRAGMENT_SIZE = 1400
PACKET_TIMEOUT = 0.5 # seconds
WINDOW_SIZE = 256

G_state = State.INPUT
G_seq_num = random.randint(0, 1000) # max uint_32 #TODO handle max uint_32 wrapping

# ACK tracking #TODO can be non global
G_acks = np.zeros(WINDOW_SIZE, dtype=bool)
G_send_times = np.zeros(WINDOW_SIZE)
G_sent_packets = [None] * WINDOW_SIZE
G_base_seq = G_seq_num  # Bottom of the window

#TODO text, file, handshake separate queue
packet_queue = queue.Queue()
handshake_queue = queue.Queue() #TODO use SimpleQueue()

#TODO packet storage
# import numpy as np

# packet_buffer = np.zeros(1000, dtype=np.uint8)  # 1000-byte buffer


# acks[packet_seq] = True



class PacketData():
    def __init__(self):
        pass

    def createPacket(self, data, ack_num: int, seq_num: int, ack=0, syn=0, fin=0, ctr=0, ftr=0, nack=0) -> bytes:
        flags = (ack << 7) | (syn << 6) | (fin << 5) | (ctr << 4) | (ftr << 3) | (nack << 2) #!| (self.ftr << 1)
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
        ftr=(flags >> 3) & 1
        nack=(flags >> 2) & 1
        # ftr=(flags >> 1) & 1

        # Does not return a dictionary for performance reasons
        return (data, ack_num, seq_num, ack, syn, fin, ctr, ftr, nack, None, None, checksum)
    
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


class FileData():
    sock = None
    peer_ip = None 
    peer_port = None
    fragment_size = None
    connection = None
    pd = None

    file_path = None
    file_name = None # Transfered file

    def __init__(self, sock, peer_ip, peer_port, fragment_size, connection, packet_data):
        self.sock = sock
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.fragment_size = fragment_size
        self.connection = connection
        self.pd = packet_data

    def sendFile(self, file_path):
        global G_state

        try:
            if os.path.exists(file_path):
                G_state = State.FILE_TRANSFER

                with packet_queue.mutex:
                    packet_queue.queue.clear()

                self.printFTInfo("Sending file '" + os.path.basename(file_path) + "'...")
                self.sendBytes(file_path)
            else:
                self.printFTInfo("File not found.")
        except Exception as e:
            self.printFTInfo("Error sending file: " + e) 

    def sendBytes(self, file_path):
        # try:
        
        file_name = os.path.basename(file_path)
        with open(file_path, 'rb') as file:
            # data = file.read()
            # fragments = self.protocol.fragmentData(data.decode('latin1'))
            # self.total_fragments = len(fragments)

            #TODO LATER seek window within the file
            # with open(file_path, "rb") as f:
            #     f.seek(packet_seq * FRAGMENT_SIZE)
            # data = f.read(FRAGMENT_SIZE)

            # Send setup packet with total_fragments and filename

            while True:
                self.connection.sendPacket(self.pd.createPacket(file_name, 0, 0, ftr=1, ctr=1)) #TODO outsource to ack resend
                self.printFTInfo("File transfer initialization packet sent...")
                try:
                    bytes = packet_queue.get(timeout=3)  # Blocks until ACK packet arrives
                    if bytes[3] and bytes[8]:
                        self.printFTInfo("File transfer rejected by peer.")
                        self.connection.abortFileTransfer()
                        return
                    
                    elif bytes[3]:
                        self.printFTInfo("Sending file: " + self.file_name)
                    break
                    #handle_packet(parsed)
                except queue.Empty:
                    self.printFTInfo("No reply to init packet...")
                    continue

            print("RECEIVED ACK PACKET FOR " + file_path)
            # setup_packet = Packet(
            #     seq_num=self.file_seq_num,
            #     ftr=1,
            #     ctr=1,
            #     data=f"{self.total_fragments:08x}|{filename}"
            # )
            # peer.sendPacket(dest_ip, dest_port, setup_packet)

            # Start sending and receiving threads #TODO
            # send_thread = threading.Thread(target=self.sendFragments, args=(peer, dest_ip, dest_port, fragments))
            # ack_thread = threading.Thread(target=self.receiveAcks, args=())

            # send_thread.start()
            # ack_thread.start()
             
            
        # except FileNotFoundError:
        #     self.printFTInfo("File not found.")
        # except Exception as e:
        #     self.printFTInfo("Error sending file: " + e)


    # def reconstructFile(self):
    #     global FILE_TRANSFERING
    #     save_path = input("Enter path to save the file << ")
    #     if not os.path.exists(save_path):
    #         print("Path does not exist, saving to default download directory...")
    #         save_path = ""
    #     elif save_path[-1:] not in ['\\', '/']:
    #         save_path += '\\'

    #     save_path += self.current_filename
    #     with open(save_path, 'wb') as f:
    #         for seq_num in sorted(self.file_fragments.keys()):
    #             f.write(self.file_fragments[seq_num].encode('latin1'))
    #     print(f"File successfully received and saved as \"{save_path}\".")
    #     FILE_TRANSFERING = False

    def printFTInfo(self, message):
        print(f"({datetime.now().strftime("%H:%M")}) [FILE_TRANSFER]: {message}")
  

class Connection():
    fragment_size = MAX_FRAGMENT_SIZE #TODO update on change

    sock = None
    src_ip = None
    src_port = None
    peer_ip = None 
    peer_port = None

    pd = None
    fd = None #TODO update fd.fragment_size on change

    def __init__(self, src_ip, src_port, peer_ip, peer_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.src_ip = src_ip
        self.src_port = src_port
        self.peer_ip = peer_ip
        self.peer_port = peer_port

        self.pd = PacketData()
        self.fd = FileData(self.sock, self.peer_ip, self.peer_port, self.fragment_size, self, self.pd)

        threading.Thread(target=receive, args=(self.sock, src_ip, src_port, self), daemon=True).start()
        threading.Thread(target=handlePackets, args=(self.peer_ip, self.peer_port, self), daemon=True).start()
        

    def handshake(self):
        global G_state
        global G_seq_num

        syn_sent = False
        syn_ack_sent = False

        printHandshakeInfo("Starting...")

        with handshake_queue.mutex:
            handshake_queue.queue.clear()

        while True:
            self.sendPacket(self.pd.createPacket('', ack_num=0, seq_num=G_seq_num, ack=0, syn=1))
            G_seq_num += 1 #! SEQ addition
            printHandshakeInfo("SYN packet sent...")
            syn_sent = True
            try:
                packet = handshake_queue.get(timeout=5)  # Blocks until packet arrives
                #handle_packet(parsed)
            except queue.Empty:
                printHandshakeInfo("No reply to SYN packet...")
                continue

            seq_num = packet[2]
            ack = packet[3]
            syn = packet[4]

            if syn_sent and syn and ack:
                printHandshakeInfo("SYN-ACK packet received...")
                printHandshakeInfo("Sending ACK packet...")
                self.sendAck(seq_num)
                printHandshakeInfo("Connected.")
                G_state = State.CONNECTED
                break

            elif syn:
                printHandshakeInfo("SYN packet received...")
                printHandshakeInfo("Sending SYN-ACK packet...")
                self.sendPacket(self.pd.createPacket('', ack_num=seq_num, seq_num=G_seq_num, ack=1, syn=1))
                syn_ack_sent = True

            elif syn_ack_sent and ack:
                printHandshakeInfo("SYN-ACK packet received...")
                printHandshakeInfo("Connected.")
                G_state = State.CONNECTED
                break
        print()

    def handleInput(self):
        global G_seq_num
        user_input = input()

        if G_state == State.FILE_RECEIVE:
            if user_input in ["Y", "y", "Yes"]:
                self.sendPacket(self.pd.createPacket("", ack_num=0, seq_num=G_seq_num, ack=1))
                G_seq_num += 1 #! SEQ addition
                return
            else:
                self.abortFileTransfer()
                self.sendPacket(self.pd.createPacket("", ack_num=0, seq_num=0, ack=1, nack=1))
                #TODO ACK NUM, make ack into a separate function for sending ack packets
                return



        #TODO
        # if user_input.startswith("/setfragsize "):
        #     try:
        #         new_size = int(user_input.split()[1])
        #         self.setFragmentSize(new_size)
        #     except ValueError:
        #         print("Invalid command. Usage: /setfragsize <size>")
        #TODO if message startsWith / and is incorrect command send warning instead of message
        if user_input.startswith("/send "):
            self.fd.file_path = user_input[6:].strip()
            self.fd.file_name = os.path.basename(self.fd.file_path)
            self.fd.sendFile(self.fd.file_path)
        # elif user_input.startswith("/disconnect"):
        #     self.trerminateConnection()
        else:
            self.sendPacket(self.pd.createPacket(user_input, ack_num=0, seq_num=G_seq_num))
            G_seq_num += 1 #! SEQ addition

    def sendPacket(self, packet: bytes):
        global G_send_times
        global G_sent_packets
        global G_seq_num
        global G_acks
        #TODO wont be slow?
        index = G_seq_num % WINDOW_SIZE 
        G_sent_packets[index] = packet
        G_send_times[index] = time.time()
        G_acks[index] = False
        self.sock.sendto(packet, (self.peer_ip, self.peer_port))

    def sendAck(self, seq_num: int):
        self.sock.sendto(self.pd.createPacket("", ack_num=seq_num, seq_num=0, ack=1), (self.peer_ip, self.peer_port))

    def abortFileTransfer(self):
        global G_state
        G_state = State.CONNECTED
        self.fd.file_name = None
        self.fd.file_path = None

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
            connection.handleInput()
        if (G_state == State.FILE_TRANSFER):
            pass
            #connection.sendPacket(connection.pd.createPacket('', ack_num=0, seq_num=0, ack=1))


def handlePackets(peer_ip, peer_port, connection):
    global G_state
    fd = connection.fd # FileData
    pd = connection.pd # PacketData

    while G_state != State.EXITING:
        try:
            packet = packet_queue.get()
            bytes = pd.parsePacket(packet) # 0:data 1:ack_num 2:seq_num 3:ack 4:syn 5:fin 6:ctr 7:ftr 8:nack 9:None 10:None 11:checksum
            #TODO replace bytes with data, ack_num ... = parsePacket()

            if (G_state == State.HANDSHAKE):
                handshake_queue.put(bytes)

            if bytes[3]: # ack
                logAck(bytes[1])
            elif not bytes[3]:
                connection.sendAck(bytes[2]) 

            if bytes[8]: # nack 
                pass
                #connection.sendPacket(G_sent_packets[TODO index bytes[1]]) # resend
            elif bytes[6] and bytes[7]: # ftr && ctr
                G_state = State.FILE_RECEIVE
                fd.file_name = bytes[0]
                print(f"Peer wants to transfer file '{bytes[0]}'; Do you accept? [Y/N]")
            elif bytes[7]: #ftr
                packet_queue.put(bytes) #TODO remove
            elif not bytes[3] and not bytes[4] and not bytes[8]: #~ !ack && !nack
                printTextMessages(peer_ip, peer_port, bytes)
        except Exception as e:
        #     #print("Receiver error:", e)
            pass


def logAck(ack_num: int):
    global G_acks
    global G_base_seq
    index = ack_num % WINDOW_SIZE
    print("logging ack: ", ack_num, ", index: ", index)
    G_acks[index] = True


def slideWindow(next_seq: int): #TODO
    global G_base_seq
    while G_base_seq < next_seq:
        index = G_base_seq % WINDOW_SIZE
        if G_acks[index]:
            G_acks[index] = False
            G_sent_packets[index] = None
            G_base_seq += 1
        else:
            break


def checkAckTimeouts(sock, address, base_seq: int, next_seq: int):
    now = time.time()
    for i in range(base_seq, next_seq):
        index = i % MAX_WINDOW_SIZE
        if not acknowledged[index] and now - sent_times[index] > PACKET_TIMEOUT:
            print(f"[Resending] seq={i}")
            sock.sendto(sent_packets[index], address)
            sent_times[index] = now


def receive(sock, src_ip, src_port, connection):
    global G_state

    sock.bind((src_ip, src_port))

    while G_state != State.EXITING:
        try:
            packet, addr = sock.recvfrom(BUFFER_SIZE)
            packet_queue.put(packet)
        except Exception as e:
            # print("Receiver error:", e)
            pass


def printTextMessages(peer_ip, peer_port, bytes):
    print(f"({datetime.now().strftime("%H:%M")}) {peer_ip}:{peer_port} >> {bytes[0]}")


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


    # def handleFragment(self, packet):
    #     global FILE_TRANSFERING
    #     crc = Packet.calculateChecksum

    #     if packet.ftr != 1:
    #         return

    #     if packet.ack == 1:  # Filename packet
    #         try:
    #             total_fragments_hex, filename = packet.data.split('|', 1)
    #             self.expected_fragments = int(total_fragments_hex, 16)
    #             self.current_filename = filename
    #             print(f"Receiving file: {filename} ({self.expected_fragments} fragments expected)")
    #         except ValueError:
    #             print("Error parsing header packet.")
    #         return

    #     if (packet.checksum == crc(packet.data.encode('utf-8'))):
    #         seq_num = packet.seq_num
    #         self.file_fragments[seq_num] = packet.data
            
    #         ack_packet = Packet(
    #             ack=1,
    #             ack_num=seq_num
    #         )
    #         peer.sendPacket(peer.dest_ip, peer.dest_port, ack_packet)

    #         self.acknowledged_frags += 1
    #         self.last_acked_seq = seq_num

    #         # Progress
    #         print(f"\rFragments > {len(self.file_fragments)}/{self.expected_fragments} received, {self.acknowledged_frags}/{self.expected_fragments} acknowledged", end="", flush=True)                

    #         # Check if file transfer is complete
    #         if len(self.file_fragments) == self.expected_fragments:
    #             self.reconstructFile()
    #             self.file_complete = True
    #             FILE_TRANSFERING = False

    #     elif (packet.ftr == 1):
    #         print(f"\nInvalid checksum for packet {packet.seq_num}")
    #         err_packet = Packet(
    #             err=1,
    #             ack_num=packet.seq_num
    #         )
    #         peer.sendPacket(peer.dest_ip, peer.dest_port, err_packet)
                
    

