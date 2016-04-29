#include <stdio.h>
#include <libnet.h>

const char *dev     = "wlan0";
const char *dst_ip  = "192.168.0.1";
const char *dst_mac = "FF:FF:FF:FF:FF:FF";

int main() {
    int dst_mac_len;
    char *device = (char*) dev;                                     /* network device */
    in_addr_t destaddr = inet_addr(dst_ip);                         /* destination ip address */
    u_int8_t *macaddr = libnet_hex_aton(dst_mac, &dst_mac_len);     /* destination mac address */
    char errbuf[LIBNET_ERRBUF_SIZE];                                /* error messages */

    /* open context */
    libnet_t *l = libnet_init(LIBNET_LINK, device, errbuf);
    if (l == NULL) {
        fprintf(stderr, "Error opening context: %s", errbuf);
        exit(1);
    }

    /* get the hardware address, ip address for the card we are using */
    libnet_ether_addr *hwaddr = libnet_get_hwaddr(l);
    u_int32_t ipaddr = libnet_get_ipaddr4(l);

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

    /* exit cleanly */
    libnet_destroy(l);
    return 0;
}
