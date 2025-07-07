the program is basically a state machine

all packets are numbered, beginning with randomly generated ISN (initial sequence number)

avoided using class with packets because when making reliable udp connection with file transfer, we have to handle too many packets so the process needs to be very minimal and fast. Just unpack, validate and return

received packets get put into a queue

handshake -> establish connection -> new Connection()

THREADS:
- always listening on a separate thread but ignores if not in receiving state

MESSAGES
- fin means end of fragmented message or the message is not fragmented (we wait for fin packet )

FILE TRANSFER


PROTOCOL:

 Bits |    Field
------|----------------------------
  32  |  Acknowledgement Number
  32  |  Sequence Number
   8  |  FLAGS
   8  |  Reserved
  16  |  Window Size
  16  |  Checksum

FLAGS:

| ACK

| SYN
| FIN
| CTR - control packet (used to for example send the expected filesize or to change fragment size)
|
|
|
|
  

https://www.cs.miami.edu/home/burt/learning/Csc524.032/notes/tcp_nutshell.html