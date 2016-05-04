#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#include <libnet.h>

struct _libnet_arp_hdr {
    u_short ar_hrd;                         /* format of hardware address */
#define ARPHRD_ETHER     1                  /* ethernet hardware format */
    u_short ar_pro;                         /* format of protocol address */
    u_char  ar_hln;                         /* length of hardware address */
    u_char  ar_pln;                         /* length of protocol addres */
    u_short ar_op;                          /* operation type */
#define ARPOP_REQUEST    1                  /* req to resolve address */
#define ARPOP_REPLY      2                  /* resp to previous request */
#define ARPOP_REVREQUEST 3                  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4                  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8                  /* req to identify peer */
#define ARPOP_INVREPLY   9                  /* resp identifying peer */

    /*
    *  These should implementation defined but I've hardcoded eth/IP.
    */
    u_char ar_sha[6];                         /* sender hardware address */
    u_char ar_spa[4];                         /* sender protocol address */
    u_char ar_tha[6];                         /* target hardware address */
    u_char ar_tpa[4];                         /* target protocol address */
};

class ARPSpoofing {
private:
    char *senderIP, *senderMAC, *receiverIP, *receiverMAC;
    u_int32_t senderIPInt32, receiverIPInt32;
    char *device = "eth0";
    u_int32_t attackCycle = 1;

    bool sendARP(char *IP, u_int32_t IPInt32);
    bool recvARP(u_int32_t IPInt32, char **MAC);
    bool relay();
    bool recover();

public:
    ARPSpoofing(char *senderIP, char *receiverIP);
    bool Init();
    bool Attack();
    bool Stop();
};

#endif // ARPSPOOFING_H
