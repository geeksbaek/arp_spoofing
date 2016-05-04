#include "arpspoofing.h"
#include <stdio.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <thread>

ARPSpoofing::ARPSpoofing(char *senderIP, char *receiverIP) {
    this->senderIP = senderIP;
    this->receiverIP = receiverIP;
}

bool ARPSpoofing::Init() {
    sockaddr_in t;
    std::thread recvARPThread;

    if (inet_aton(this->senderIP, &t.sin_addr) == 0) {
        printf("Error 1");
        return false;
    }
    this->senderIPInt32 = (u_int32_t) t.sin_addr.s_addr;

    if (inet_aton(this->receiverIP, &t.sin_addr) == 0) {
        printf("Error 2");
        return false;
    }
    this->receiverIPInt32 = (u_int32_t) t.sin_addr.s_addr;

    recvARPThread = std::thread([this]{
        ARPSpoofing::recvARP(this->senderIPInt32, &this->senderMAC);
    });
    if (ARPSpoofing::sendARP(this->senderIP, this->senderIPInt32) == false) {
        printf("Error 3");
        return false;
    }
    recvARPThread.join();

    recvARPThread = std::thread([this]{
        ARPSpoofing::recvARP(this->receiverIPInt32, &this->receiverMAC);
    });
    if (ARPSpoofing::sendARP(this->receiverIP, this->receiverIPInt32) == false) {
        printf("Error 4");
        return false;
    }
    recvARPThread.join();

    return true;
}

bool ARPSpoofing::sendARP(char *IP, u_int32_t IPInt32) {
    int _t;
    in_addr_t dstIP = inet_addr(this->senderIP);
    u_int8_t *dstMAC = libnet_hex_aton("ff:ff:ff:ff:ff:ff", &_t);
    u_int8_t *dstHardware = libnet_hex_aton("00:00:00:00:00:00", &_t);
    char errbuf[LIBNET_ERRBUF_SIZE];

    /* open context */
    libnet_t *l = libnet_init(LIBNET_LINK, this->device, errbuf);
    if (l == NULL) {
        fprintf(stderr, "Error opening context: %s", errbuf);
        return false;
    }

    /* get the hardware address, ip address for the card we are using */
    u_int32_t srcIP = libnet_get_ipaddr4(l);
    libnet_ether_addr *srcMAC = libnet_get_hwaddr(l);

    /* build the ARP header */
    libnet_ptag_t arp = libnet_autobuild_arp(ARPOP_REQUEST, (u_int8_t*) srcMAC, (u_int8_t*) &srcIP, dstHardware, (u_int8_t*) &dstIP, l);
    if (arp == -1) {
        fprintf(stderr, "Unable to build ARP header: %s\n", libnet_geterror(l));
        return false;
    }

    /* build the ethernet header */
    libnet_ptag_t eth = libnet_build_ethernet(dstMAC, (u_int8_t*) srcMAC, ETHERTYPE_ARP, NULL, 0, l,0);
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

    /* exit cleanly */
    libnet_destroy(l);
    return true;
}

bool ARPSpoofing::recvARP(u_int32_t IPInt32, char **MAC) {
    pcap_t *handle;                 /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(this->device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        sprintf(*MAC, "Couldn't open device %s: %s\n", this->device, errbuf);
        return false;
    }

    pcap_pkthdr header;
    const u_char *packet;

    while (true) {
        packet = pcap_next(handle, &header);

        libnet_ethernet_hdr *ethHeader = (libnet_ethernet_hdr*) packet;
        if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
            _libnet_arp_hdr *arpHeader = (_libnet_arp_hdr*) (packet + sizeof(libnet_ethernet_hdr));
            printf("%x\n", arpHeader->ar_sha);
            if (ntohs(arpHeader->ar_op) == ARPOP_REPLY && (*(u_int32_t*) arpHeader->ar_spa) == IPInt32) {
                char buf[18];
                *MAC = ether_ntoa_r((ether_addr*)arpHeader->ar_sha, buf);
                pcap_close(handle);
                return true;
            }
        }
    }
}
