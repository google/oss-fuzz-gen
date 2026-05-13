// This fuzz driver is generated for library libpcap, aiming to fuzz the following functions:
// pcap_open_dead at pcap.c:4696:1 in pcap.h
// pcap_setfilter at pcap.c:3948:1 in pcap.h
// pcap_close at pcap.c:4323:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_get_selectable_fd at pcap.c:3593:1 in pcap.h
// pcap_get_required_select_timeout at pcap.c:3599:1 in pcap.h
// pcap_setnonblock at pcap.c:3662:1 in pcap.h
// pcap_close at pcap.c:4323:1 in pcap.h
// pcap_get_required_select_timeout at pcap.c:3599:1 in pcap.h
// pcap_dispatch at pcap.c:2955:1 in pcap.h
// pcap_get_required_select_timeout at pcap.c:3599:1 in pcap.h
// pcap_dispatch at pcap.c:2955:1 in pcap.h
// pcap_dispatch at pcap.c:2955:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_close at pcap.c:4323:1 in pcap.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>

static void dummy_packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // This is a dummy packet handler for pcap_dispatch
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_program)) {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) {
        return 0;
    }

    struct bpf_program filter;
    memcpy(&filter, Data, sizeof(struct bpf_program));

    // pcap_setfilter
    if (pcap_setfilter(handle, &filter) != 0) {
        pcap_close(handle);
        return 0;
    }

    // pcap_geterr
    char *error_msg = pcap_geterr(handle);

    // pcap_get_selectable_fd
    int fd = pcap_get_selectable_fd(handle);

    // pcap_get_required_select_timeout
    const struct timeval *timeout = pcap_get_required_select_timeout(handle);

    // pcap_setnonblock
    if (pcap_setnonblock(handle, 1, errbuf) != 0) {
        pcap_close(handle);
        return 0;
    }

    // pcap_get_required_select_timeout again after setting non-blocking
    timeout = pcap_get_required_select_timeout(handle);

    // pcap_dispatch
    int dispatch_result = pcap_dispatch(handle, 10, dummy_packet_handler, NULL);

    // pcap_get_required_select_timeout
    timeout = pcap_get_required_select_timeout(handle);

    // pcap_dispatch again
    dispatch_result = pcap_dispatch(handle, 10, dummy_packet_handler, NULL);

    // pcap_dispatch again
    dispatch_result = pcap_dispatch(handle, 10, dummy_packet_handler, NULL);

    // pcap_geterr
    error_msg = pcap_geterr(handle);

    // pcap_close
    pcap_close(handle);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
