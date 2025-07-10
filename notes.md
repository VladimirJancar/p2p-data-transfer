the program is basically a state machine

all packets are numbered, beginning with randomly generated ISN (initial sequence number)
"TCP uses a sequence number to identify each byte of data. The sequence number identifies the order of the bytes sent from each computer so that the data can be reconstructed in order, regardless of any out-of-order delivery that may occur. The sequence number of the first byte is chosen by the transmitter for the first packet, which is flagged SYN. This number can be arbitrary, and should, in fact, be unpredictable to defend against TCP sequence prediction attacks. "

avoided using class with packets because when making reliable udp connection with file transfer, we have to handle too many packets so the process needs to be very minimal and fast. Just unpack, validate and return

received packets get put into a queue

handshake -> establish connection -> new Connection()

THREADS:
- always listening on a separate thread but ignores if not in receiving state

RELIABLE TRANSFER - Selective Repeat Sliding Window
- all packets sent will be put in a dictionary of the size of the sliding window. W

MESSAGES
- fin means end of fragmented message or the message is not fragmented (we wait for fin packet )

FILE TRANSFER
- send a CTR packet with filename and length and wain for ACK before proceeding
- ask to accept, send ack if yes or ack/nack if not


PROTOCOL:

 Bits |    Field
------|----------------------------
  32  |  Acknowledgement Number
  32  |  Sequence Number
   8  |  FLAGS
   8  |  Reserved
  16  |  Checksum

FLAGS:

| ACK

| SYN
| FIN - terminate conection and drop in-transit data
| CTR - control packet (used to for example send the expected filesize or to change fragment size)
|
|
|
|
  

https://www.cs.miami.edu/home/burt/learning/Csc524.032/notes/tcp_nutshell.html
https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Reliable_transmission