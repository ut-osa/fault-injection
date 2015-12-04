/*
 * swifi.c -- User level control for fault injection
 *
 * Copyright (c) 2014 <anonymous submission>
 *
 * 
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/swifi-user.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct swifi_types {
    const char *name;
    const int code;
};
#define SWIFI_TYPE(n) (struct swifi_types){.name = #n, .code = n##_FAULT}
struct swifi_types types[] = {
    SWIFI_TYPE(TEXT),
    SWIFI_TYPE(STACK),
    SWIFI_TYPE(INIT),
    SWIFI_TYPE(NOP),
    SWIFI_TYPE(DST),
    SWIFI_TYPE(SRC),
    SWIFI_TYPE(BRANCH),
    SWIFI_TYPE(PTR),
    SWIFI_TYPE(FREE),
    SWIFI_TYPE(BCOPY),
    SWIFI_TYPE(INVERT),
    SWIFI_TYPE(MEM_LEAK),
    SWIFI_TYPE(INTERFACE),
    SWIFI_TYPE(DIRECT),
    SWIFI_TYPE(PANIC),
    SWIFI_TYPE(WHILE1),
    SWIFI_TYPE(IRQ),
    SWIFI_TYPE(ALLOC),
    SWIFI_TYPE(INTRPT),
    SWIFI_TYPE(ALLOC_SZ),
    SWIFI_TYPE(BLOCKING),
    SWIFI_TYPE(OBO),
    SWIFI_TYPE(FLOAT),
    SWIFI_TYPE(VAR),
    SWIFI_TYPE(ATOMIC),
    SWIFI_TYPE(UNLOCK),
    SWIFI_TYPE(KERNEL),
    SWIFI_TYPE(FS),
};
#define NUM_TYPES (sizeof(types) / sizeof(types[0]))

int parse_type(const char *type)
{
    int rc = -1, i;
    for (i = 0; i < NUM_TYPES; i++) {
        if (strcasecmp(type, types[i].name) == 0) {
            rc = types[i].code;
            break;
        }
    }
    return rc;
}

int usage(char *name)
{
    printf("%s: <target> [type:text] [num_faults:1] [rand_seed:1]\n", name);
    return -1;
}

struct swifi_result results[1024];
int main(int argc, char *argv[])
{
    int rc;
    int fd = open("/dev/swifi", O_RDWR);
    char buf[256] = {0};
    char *sep = NULL;
    struct swifi_fault_params params;

    if (fd < 0) {
        perror("open /dev/swifi");
        return errno;
    }

    if (argc <= 1) {
        usage(argv[0]);
        goto out;
    }
    if (strcmp(argv[1], "debug") == 0) {
        rc = ioctl(fd, SWIFI_VERBOSE);
        goto out;
    }

    if (strncmp(argv[1], "range", 5) == 0) {
        snprintf(buf, 8, "range");
        *(unsigned long *)(buf + 8) = 0xffffffff00000000ULL | (unsigned long long)strtoll(argv[1] + 6, &sep, 0);
        sep++;
        *(unsigned long *)(buf + 16) = (unsigned long long)strtoll(sep, NULL, 0);
        printf("%s:%llx:%llx\n", buf, *(unsigned long long *)(buf + 8), *(unsigned long long *)(buf + 16));
        rc = ioctl(fd, SWIFI_SET_TARGET, buf);
    } else {
        rc = ioctl(fd, SWIFI_SET_TARGET, argv[1]);
    }

    params.record = results;
    params.type = 0;
    params.faults = 1;
    params.seed = 1;

    if (argc > 2) {
        char *end = NULL;
        params.type = strtol(argv[2], &end, 0);
        if (argv[2] == end) {
            if ((params.type = parse_type(argv[2])) == -1) {
                return usage(argv[0]);
            }
        }
    }
    if (argc > 3) {
        params.faults = strtol(argv[3], NULL, 0);
    }
    if (argc > 4) {
        params.seed = strtol(argv[4], NULL, 0);
    }

    rc = ioctl(fd, SWIFI_DO_FAULTS, &params);

 out:
    close(fd);
    return rc;
}
