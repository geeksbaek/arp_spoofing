#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#include <libnet.h>
#include <pcap.h>
#include <functional>

#define MAC_ADDR_LEN 6
#define IPv4_ADDR_LEN 4

struct _libnet_arp_hdr {
    u_short ar_hrd;                 /* format of hardware address */
    u_short ar_pro;                 /* format of protocol address */
    u_char  ar_hln;                 /* length of hardware address */
    u_char  ar_pln;                 /* length of protocol addres */
    u_short ar_op;                  /* operation type */
    u_char ar_sha[MAC_ADDR_LEN];    /* sender hardware address */
    u_char ar_spa[IPv4_ADDR_LEN];   /* sender protocol address */
    u_char ar_tha[MAC_ADDR_LEN];    /* target hardware address */
    u_char ar_tpa[IPv4_ADDR_LEN];   /* target protocol address */
};

class ARPSpoofing {
private:
    u_int8_t s_ip[IPv4_ADDR_LEN];   // sender ip addr
    u_int8_t s_mac[MAC_ADDR_LEN];   // sender mac addr
    u_int8_t r_ip[IPv4_ADDR_LEN];   // receiver ip addr
    u_int8_t r_mac[MAC_ADDR_LEN];   // receiver mac addr
    u_int8_t a_ip[IPv4_ADDR_LEN];   // attacker ip addr
    u_int8_t a_mac[MAC_ADDR_LEN];   // attacker mac addr

    u_int8_t broadcast[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int8_t zerofill[MAC_ADDR_LEN] = {0,};
    u_int8_t test[MAC_ADDR_LEN] = {1,2,3,4,5,6};

    char *device;
    bool kill_attack = false;
    bool fin_attack = false;
    bool kill_relay = false;
    bool fin_relay = false;
    int attack_cycle = 1;

    void _get_mac_addr_through_arp_request(u_int8_t *t_ip, u_int8_t *t_mac);
    void _relay();
    void __read_packet(std::function<void(pcap_t *handle, pcap_pkthdr *header, const u_char *packet)> cb);
    void _send_ARP_request(u_int8_t *d_ip, uint8_t *d_mac, u_int8_t *s_ip, uint8_t *s_mac);
    void _send_ARP_response(u_int8_t *d_ip, uint8_t *d_mac, u_int8_t *s_ip, uint8_t *s_mac);
    bool __send_ARP(u_int8_t *d_ip, uint8_t *d_mac, u_int8_t *s_ip, uint8_t *s_mac, u_int16_t arp_type);

    static bool _bytes_equal(u_int8_t *bytes_a, u_int8_t *bytes_b, int size);
    static void _bytes_print(u_int8_t *bytes_array, int size);
    static void _char_bytes_to_uint8_bytes(char *char_array, u_int8_t *bytes_array);
    static char* _uint8_bytes_to_char_bytes(u_int8_t *bytes_array);
    static u_int8_t* _reverse_byte_order(u_int8_t *bytes_array, int size);

public:
    ARPSpoofing();
    bool Init(char *s_ip_str, char *r_ip_str);
    void Relay();
    void Relay_Stop();
    void Attack();
    void Attack_Stop();
    void Recover();
};

#endif // ARPSPOOFING_H
