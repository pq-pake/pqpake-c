#ifndef PQPAKE_H
#define PQPAKE_H
#include <stdint.h>
#define PQPAKE_PROTO_CAKE_KYBER1024 0x01
#define PQPAKE_PROTO_OCAKE_KYBER1024 0x02

typedef struct pqpake_header {
  /**
   * The protocol version of the message.
   * This is used to determine how to interpret the rest of the buffer message.
   */
  uint8_t protocol;
} pqpake_header;

#endif  // PQPAKE_H
