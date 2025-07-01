the program is basically a state machine

THREADS:
- always listening on a separate thread but ignores if not in receiving state


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
| 
|
|
|
|
  