/*
 * netcut-launcher - menjalankan netcut.py dengan CAP_NET_RAW saja.
 *
 * Capture AF_PACKET butuh CAP_NET_RAW, sedangkan nftables butuh
 * CAP_NET_ADMIN. Memberikan CAP_NET_RAW lewat setcap membuat mode monitor
 * bisa jalan tanpa password sudo, tanpa memberi hak admin penuh.
 *
 * Build:
 *   gcc -O2 -o netcut-launcher launcher.c
 *   sudo setcap cap_net_raw+ep ./netcut-launcher
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifndef NETCUT_PY
#define NETCUT_PY "/home/aryoks/netcut-linux/netcut.py"
#endif

#ifndef PYTHON_BIN
#define PYTHON_BIN "/usr/bin/python3"
#endif

int main(int argc, char **argv) {
    char **args = calloc((size_t)argc + 3, sizeof(char *));
    if (!args) {
        fprintf(stderr, "netcut-launcher: out of memory\n");
        return 1;
    }

    int n = 0;
    args[n++] = (char *)PYTHON_BIN;
    args[n++] = (char *)NETCUT_PY;
    for (int i = 1; i < argc; i++) {
        args[n++] = argv[i];
    }
    args[n] = NULL;

    execv(PYTHON_BIN, args);
    fprintf(stderr, "netcut-launcher: gagal menjalankan %s: %s\n",
            PYTHON_BIN, strerror(errno));
    return 127;
}
