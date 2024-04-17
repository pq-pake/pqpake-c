#ifndef PAKE_H
#define PAKE_H
#include <stdint.h>
#define PAKE_PROTO_CAKE_KYBER1024 0x01
#define PAKE_PROTO_OCAKE_KYBER1024 0x02

typedef struct pake_header {
  /**
   * The protocol version of the message.
   * This is used to determine how to interpret the rest of the buffer message.
   */
  uint8_t protocol;
} pake_header;

#endif  // PAKE_H
