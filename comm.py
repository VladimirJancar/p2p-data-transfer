import socket
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
    