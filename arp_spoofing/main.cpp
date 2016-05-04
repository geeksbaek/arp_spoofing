#include <iostream>
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

    printf("sender IP Address : %s\n", argv[1]);
    printf("receiver IP Address : %s\n", argv[2]);

    ARPSpoofing ArpSpoofer = ARPSpoofing(argv[1], argv[2]);

    ArpSpoofer.Init();


    return 0;
}
