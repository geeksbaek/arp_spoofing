#include <stdio.h>
#include "arpspoofing.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Invaild Arguments.\n");
        exit(1);
    }

    ARPSpoofing ArpSpoofer = ARPSpoofing(argv[1], argv[2]);

    if (ArpSpoofer.Init() == false) {
        fprintf(stderr, "Initialize Failed.\n");
        exit(1);
    }

    ArpSpoofer.Attack();
    printf(">> Attack started. If want stop attack, Press any button.");

    getchar();

    ArpSpoofer.Stop();
    printf(">> Attack Stopped. ARP table of all users have been recovered.\n");

    return 0;
}
