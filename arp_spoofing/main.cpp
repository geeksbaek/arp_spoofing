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
    printf(">> Attack started. If want stop attack, Press any button.\n");

    getchar();

    ArpSpoofer.Stop();
    printf(">> Attack Stopped.\n");

    ArpSpoofer.Recover();
    printf(">> ARP table have been recovered.\n");

    return 0;
}
