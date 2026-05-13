// This fuzz driver is generated for library libpcap, aiming to fuzz the following functions:
// pcap_open_offline at savefile.c:388:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_setnonblock at pcap.c:3662:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_dispatch at pcap.c:2955:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_stats at pcap.c:3989:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_geterr at pcap.c:3612:1 in pcap.h
// pcap_close at pcap.c:4323:1 in pcap.h
// pcap_freecode at gencode.c:1493:1 in pcap.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

static void dummy_packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // Dummy packet handler
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_insn)) {
        return 0;
    }

    // Prepare a dummy file
    FILE *file = fopen("./dummy_file", "w");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Initialize a pcap_t pointer
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("./dummy_file", errbuf);
    if (handle == NULL) {
        return 0;
    }

    // Invoke pcap_geterr
    char *error = pcap_geterr(handle);

    // Invoke pcap_setnonblock
    int nonblock = 1;
    int result = pcap_setnonblock(handle, nonblock, errbuf);
    if (result == PCAP_ERROR) {
        error = pcap_geterr(handle);
    }

    // Invoke pcap_dispatch
    result = pcap_dispatch(handle, -1, dummy_packet_handler, NULL);
    if (result == PCAP_ERROR) {
        error = pcap_geterr(handle);
    }

    // Invoke pcap_stats
    struct pcap_stat stats;
    result = pcap_stats(handle, &stats);
    if (result == PCAP_ERROR) {
        error = pcap_geterr(handle);
    }

    // Invoke pcap_geterr again
    error = pcap_geterr(handle);

    // Close the pcap handle
    pcap_close(handle);

    // Prepare a bpf_program for pcap_freecode
    struct bpf_program program;
    program.bf_len = Size / sizeof(struct bpf_insn);
    program.bf_insns = (struct bpf_insn *)malloc(Size);
    if (program.bf_insns) {
        memcpy(program.bf_insns, Data, Size);
        pcap_freecode(&program);
    }

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
