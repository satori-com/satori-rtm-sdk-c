#include "rtm_internal.h"

/**
 * Transform between host and network order for shorts
 */
uint16_t _rtm_ntohs(uint16_t in) {
  uint16_t test = 1;
  if(*(uint8_t *)&test == 1) {
    // Little endian
    return ((in & 0xFF) << 8) | ((in & 0xFF00) >> 8);
  }
  return in;
}

/**
 * Transform between host and network order for shorts
 */
 uint32_t _rtm_ntohl(uint32_t in) {
   uint16_t test = 1;
   if(*(uint8_t *)&test == 1) {
     // Little endian
     return ((in & 0x000000FF) << 24) | ((in & 0xFF000000) >> 24) |
            ((in & 0x0000FF00) << 8) | ((in & 0x00FF0000) >> 8);
   }
   return in;
 }

/**
 * Transform between host and network order for unsigned 64bit
 */
uint64_t _rtm_ntohll(uint64_t in) {
  uint16_t test = 1;
  if(*(uint8_t *)&test == 1) {
    // Little endian
    return ((in & UINT64_C(0xFF00000000000000)) >> 56) |
           ((in & UINT64_C(0x00000000000000FF)) << 56) |
           ((in & UINT64_C(0x00FF000000000000)) >> 40) |
           ((in & UINT64_C(0x000000000000FF00)) << 40) |
           ((in & UINT64_C(0x0000FF0000000000)) >> 24) |
           ((in & UINT64_C(0x0000000000FF0000)) << 24) |
           ((in & UINT64_C(0x000000FF00000000)) >> 8) |
           ((in & UINT64_C(0x00000000FF000000)) << 8);
  }
  return in;
}
