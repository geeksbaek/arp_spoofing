#include <stdio.h>
#include "arpspoofing.h"

bool checkArgValidation(int argc, char *argv[]) {
    if (argc != 3) {
        return false;
    }
    return true;
}

int main(int argc, char *argv[]) {
    if (checkArgValidation(argc, argv) == false) {
        fprintf(stderr, "Invaild Arguments.\n");
        exit(1);
    }

    ARPSpoofing ArpSpoofer = ARPSpoofing(argv[1], argv[2]);

    if (ArpSpoofer.Init() == false) {
        fprintf(stderr, ">> Initialize Failed.\n");
        exit(1);
    }
    printf(">> Initialize Successed.\n");

    if (ArpSpoofer.Attack() == false) {
        fprintf(stderr, ">> Attack Failed.\n");
        exit(1);
    }
    printf(">> Attack started. If want stop attack, Press any button.");

    getchar();

    ArpSpoofer.Stop();
    printf(">> Attack Stopped. ARP table of all users have been recovered.");

    return 0;
}
