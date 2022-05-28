#ifndef __iphdr_h__
#define __iphdr_h__

#include <stdint.h>
#include "ip.h"
struct IpHdr
{
    uint8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    uint8_t ip_tos;       /* type of service */
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    Ip ip_src;
    Ip ip_dst;
};
#endif