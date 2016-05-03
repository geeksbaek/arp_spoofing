/*
    실행 : arpspoof <sender ip> <receiver ip>
    설명 : attacker는 sender를 감염(infection)시키고,
           sender와 receiver로 가는 ip packet을 relay시켜 준다.
*/

#include <stdio.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <thread>

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

bool checkArgValidation(int argc, char *argv[]);
bool sendARPRequest(char *targetIP, sockaddr_in *targetAddress);
void recvARPResponse(char *targetIP, u_int16_t targetIPInt, char *recvMAC);
void sendARPInfection(char *targetIP);
void relaySpoofedPacket();

void _pcap_loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void _packet_redirect(const u_char *packet, u_int32_t len);

const char *dev = "eth0";
const int ARRACK_CYCLE  = 1; // seconds

sockaddr_in SenderAddress;
sockaddr_in ReceiverAddress;

int main(int argc, char *argv[]) {
    if (checkArgValidation(argc, argv) == false) {
        fprintf(stderr, "Invaild Arguments.\n");
        exit(1);
    }

    printf("%d\n", SenderAddress.sin_addr.s_addr);

    char *senderIP = argv[1];
    char *receiverIP = argv[2];

    printf("sender IP Address : %s\n", senderIP);
    printf("receiver IP Address : %s\n", receiverIP);

    sendARPRequest(senderIP, &SenderAddress);

    return 0;
}

bool checkArgValidation(int argc, char *argv[]) {
    if (argc != 3 || inet_aton(argv[1], &SenderAddress.sin_addr) == 0
            || inet_aton(argv[2], &ReceiverAddress.sin_addr) == 0) {
        return false;
    }
    return true;
}

bool sendARPRequest(char *targetIP, sockaddr_in *targetAddress) {
    int _t;
    char *device = (char*) dev;
    in_addr_t dstIP = inet_addr(targetIP);
    u_int8_t *dstMAC = libnet_hex_aton("ff:ff:ff:ff:ff:ff", &_t);
    u_int8_t *dstHardware = libnet_hex_aton("00:00:00:00:00:00", &_t);
    char errbuf[LIBNET_ERRBUF_SIZE];

    /* open context */
    libnet_t *l = libnet_init(LIBNET_LINK, device, errbuf);
    if (l == NULL) {
        fprintf(stderr, "Error opening context: %s", errbuf);
        return false;
    }

    /* get the hardware address, ip address for the card we are using */
    u_int32_t srcIP = libnet_get_ipaddr4(l);
    libnet_ether_addr *srcMAC = libnet_get_hwaddr(l);

    /* build the ARP header */
    libnet_ptag_t arp = libnet_autobuild_arp(
                ARPOP_REQUEST,      /* operation */
                (u_int8_t*) srcMAC, /* source hardware addr */
                (u_int8_t*) &srcIP, /* source protocol addr */
                dstHardware,        /* target hardware addr */
                (u_int8_t*) &dstIP, /* target protocol addr */
                l);                 /* libnet context */


    if (arp == -1) {
        fprintf(stderr, "Unable to build ARP header: %s\n", libnet_geterror(l));
        return false;
    }

    /* build the ethernet header */
    libnet_ptag_t eth = libnet_build_ethernet(
                dstMAC,             /* destination address */
                (u_int8_t*) srcMAC, /* source address */
                ETHERTYPE_ARP,      /* type of encasulated packet */
                NULL,               /* pointer to payload */
                0,                  /* size of payload */
                l,                  /* libnet context */
                0);                 /* libnet protocol tag */

    if (eth == -1) {
        fprintf(stderr, "Unable to build Ethernet header: %s\n", libnet_geterror(l));
        return false;
    }

    /* write the packet */
    if (libnet_write(l) == -1) {
        fprintf(stderr, "Unable to send packet: %s\n", libnet_geterror(l));
        return false;
    }

    printf("ARP request packet was successfully sended.\n");

    char *recvMAC;
    recvARPResponse(targetIP, (u_int16_t) targetAddress->sin_addr.s_addr, recvMAC);

    printf("received MAC Address : %s\n", recvMAC);

    /* exit cleanly */
    libnet_destroy(l);
    return true;
}

void recvARPResponse(char *targetIP, u_int16_t targetIPInt, char *recvMAC) {
    pcap_t *handle;                 /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        sprintf(recvMAC, "Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }

    pcap_pkthdr header;
    const u_char *packet;

    while (true) {
        packet = pcap_next(handle, &header);

        libnet_ethernet_hdr *ethHeader = (libnet_ethernet_hdr*) packet;
        if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
            _libnet_arp_hdr *arpHeader = (_libnet_arp_hdr*) (packet + sizeof(libnet_ethernet_hdr));
            printf("%d vs %d\n", *(u_int16_t*) arpHeader->ar_spa, targetIPInt);
            if (arpHeader->ar_op == ARPOP_REPLY && (*(u_int16_t*) arpHeader->ar_spa) == targetIPInt) {
                pcap_close(handle);
                ether_ntoa_r((ether_addr*)arpHeader->ar_sha, recvMAC);
                return;
            }
        }
    }
}
