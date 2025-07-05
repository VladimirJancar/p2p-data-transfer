import socket
import struct
import threading
from enum import Enum

class State(Enum):
    INPUT = 0
    HANDSHAKE = 1
    CONNECTED = 2

# PORT = 8880;PEER_PORT = 8888
PORT = 8888;PEER_PORT = 8880
PEER_IP = "127.0.0.1"

BUFFER_SIZE = 1024
MAX_FRAGMENT_SIZE = 1400

G_state = State.INPUT


class Communication():
    fragment_size = MAX_FRAGMENT_SIZE

    def __init__(self):
        pass

    def end():
        pass

    def heartbeat():
        pass
        

class PacketData():

    def __init__(self):
        pass

    def createPacket(self, data, ack_num: int, seq_num: int, window_size: int, ack=0, syn=0, fin=0, ctr=0) -> bytes:
        flags = (ack << 7) | (syn << 6) | (fin << 5) | (ctr << 4) #!| (self.sfs << 3) | (self.lfg << 2) | (self.ftr << 1)
        checksum = 0 #self.calculateChecksum(data.encode('utf-8'))

        # if (self.ftr==1 and self.seq_num==2 and CORRUPT):
        #     checksum = 0
        #     CORRUPT = False

        header = struct.pack(
            '!IIBHH',#! SIZE
            ack_num,          # 32b
            seq_num,          # 32b
            flags,            # 8b
            window_size,      # 16b
            checksum,         # 16b
        )
        #TODO checksum header+payload 
        return header + data.encode('utf-8')

    def parsePacket(self, packet: bytes):
        header = packet[:13]
        ack_num, seq_num, flags, window_size, checksum = struct.unpack('!IIBHH', header)
        data = packet[13:].decode('utf-8') #! 13:
        ack=(flags >> 7) & 1
        syn=(flags >> 6) & 1
        fin=(flags >> 5) & 1
        ctr=(flags >> 4) & 1
        # sfs=(flags >> 3) & 1
        # lfg=(flags >> 2) & 1
        # ftr=(flags >> 1) & 1

        return (ack_num, seq_num, ack, syn, fin, ctr, window_size, checksum, data)
    
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


def main():
    src_ip = PEER_IP
    peer_ip = PEER_IP #input("[INPUT] peer IP address: ").strip()
    src_port = PORT #int(input("[INPUT] listening port: ").strip())
    peer_port =  PEER_PORT #int(input("[INPUT] peer port: ").strip())

    #TODO separate
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    threading.Thread(target=receive, args=(sock, src_ip, src_port), daemon=True).start()

    #state = State.HANDSHAKE
    #TODO handshake

    G_state = State.CONNECTED
    
    while True:
        if (G_state == State.CONNECTED):
            handleInput(sock, peer_ip, peer_port)


def receive(sock, src_ip, src_port):
    pd = PacketData()
    sock.bind((src_ip, src_port))

    while True:
        packet, addr = sock.recvfrom(BUFFER_SIZE)
        bytes = pd.parsePacket(packet)
        
        print(f"{addr[0]}:{addr[1]} >> {bytes[8]}")


def handleInput(sock, peer_ip, peer_port):
    user_input = input("\n")

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
    packet = pd.createPacket(user_input, 0, 0, 0)
    sock.sendto(packet, (peer_ip, peer_port))


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


if __name__ == "__main__":
    main()
    