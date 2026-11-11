#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap/pcap.h"
#include "/src/libpcap/pcap/bpf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_insn)) {
        return 0; // Not enough data to proceed
    }

    // Write the input data to a dummy file
    write_dummy_file(Data, Size);

    // Prepare an error buffer
    char errbuf[PCAP_ERRBUF_SIZE];

    // Prepare a dummy pcap_t structure
    pcap_t *pcap_handle = pcap_open_offline("./dummy_file", errbuf);
    if (!pcap_handle) {
        return 0;
    }

    // Initialize BPF instruction and program
    struct bpf_insn dummy_insn = {0};
    memcpy(&dummy_insn, Data, sizeof(dummy_insn));

    struct bpf_program bpf_prog;
    bpf_prog.bf_len = 1;
    bpf_prog.bf_insns = &dummy_insn;

    // Validate BPF program
    int valid = bpf_validate(bpf_prog.bf_insns, bpf_prog.bf_len);
    if (!valid) {
        pcap_close(pcap_handle);
        return 0;
    }

    // Dump BPF program
    int option = Data[0] % 3; // Randomize option based on input data
    bpf_dump(&bpf_prog, option);

    // Prepare packet header and data
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    // Use pcap_next_ex to read the next packet
    int result = pcap_next_ex(pcap_handle, &header, &pkt_data);

    // Get error if any
    char *err_msg = pcap_geterr(pcap_handle);
    (void)err_msg; // Suppress unused variable warning

    // Offline filter test
    if (header && pkt_data) {
        pcap_offline_filter(&bpf_prog, header, pkt_data);
    }

    // Cleanup
    pcap_close(pcap_handle);
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
