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

#define MAC_ADDR_LEN 18

class ARPSpoofing {
private:
    char        *senderIP;
    uint8_t     senderMAC[MAC_ADDR_LEN];
    u_int32_t   senderIPInt32;
    char        *receiverIP;
    uint8_t     receiverMAC[MAC_ADDR_LEN];
    u_int32_t   receiverIPInt32;
    char        *device;
    u_int32_t   attackCycle = 1;
    bool        exitFlag = false;

    bool sendARPReq(char *_dstIP);
    bool sendARPResp(char *_dstIP, uint8_t *_dstMAC, char *_srcIP, uint8_t *_srcMAC);
    bool recvARPResp(u_int32_t srcIPInt32, uint8_t *recvMAC);
    bool _sendARP(char *_dstIP, uint8_t *_dstMAC, char *_srcIP, uint8_t *_srcMAC, u_int16_t arpType);
    bool relay();
    void recover();

public:
    ARPSpoofing(char *senderIP, char *receiverIP);
    bool Init();
    void Attack();
    bool Stop();
};

#endif // ARPSPOOFING_H
