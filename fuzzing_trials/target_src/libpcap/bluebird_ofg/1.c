#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "pcap/pcap.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    pcap_t *pcap_handle;
    struct bpf_program bpf_prog;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ensure that the size is large enough to contain a valid filter expression
    if (size < 1) {
        return 0;
    }

    // Initialize pcap handle
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of pcap_open_dead
    pcap_handle = pcap_open_dead(1, 65535);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (pcap_handle == NULL) {
        return 0;
    }

    // Create a filter expression from the input data
    char *filter_exp = (char *)malloc(size + 1);
    if (filter_exp == NULL) {
        pcap_close(pcap_handle);
        return 0;
    }
    memcpy(filter_exp, data, size);
    filter_exp[size] = '\0'; // Null-terminate the filter expression

    // Compile the filter expression
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 3 of pcap_compile
    if (pcap_compile(pcap_handle, &bpf_prog, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == 0) {
    // End mutation: Producer.REPLACE_ARG_MUTATOR
        // Apply the compiled filter
        pcap_setfilter(pcap_handle, &bpf_prog);

        // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from pcap_setfilter to pcap_offline_filter using the plateau pool
        struct pcap_pkthdr header;
        int ret_pcap_offline_filter_mthat = pcap_offline_filter(&bpf_prog, &header, data);
        if (ret_pcap_offline_filter_mthat < 0){
        	return 0;
        }
        // End mutation: Producer.SPLICE_MUTATOR
        
        pcap_freecode(&bpf_prog);
    }

    // Clean up
    free(filter_exp);
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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
