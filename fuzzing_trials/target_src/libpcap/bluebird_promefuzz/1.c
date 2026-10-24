#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap/pcap.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void handle_pcap_error(pcap_t *handle) {
    if (handle) {
        char *err = pcap_geterr(handle);
        if (err) {
            fprintf(stderr, "PCAP Error: %s\n", err);
        }
    }
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Convert the first byte of data to an integer for status code
    int status_code = Data[0];

    // 1. Invoke pcap_statustostr
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function pcap_statustostr with pcap_tstamp_type_val_to_description
    const char *status_str1 = pcap_tstamp_type_val_to_description(status_code);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // 2. Invoke pcap_geterr (initially with a null handle)
    pcap_t *handle = NULL;
    char *err1 = pcap_geterr(handle);

    // 3. Invoke pcap_statustostr again
    const char *status_str2 = pcap_statustostr(status_code);

    // 4. Invoke pcap_geterr again
    char *err2 = pcap_geterr(handle);

    // 5. Invoke pcap_open_live
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live("any", 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 0;
    }

    // 6. Invoke pcap_fileno
    int fd = pcap_fileno(handle);
    if (fd == PCAP_ERROR) {
        handle_pcap_error(handle);
    }

    // Prepare the filter string, ensuring it is null-terminated
    char filter_exp[256];
    size_t filter_len = Size < 255 ? Size : 255;
    memcpy(filter_exp, Data, filter_len);
    filter_exp[filter_len] = '\0';

    struct bpf_program fp;

    // 7. Invoke pcap_compile
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 3 of pcap_compile
    if (pcap_compile(handle, &fp, filter_exp, 64, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
    // End mutation: Producer.REPLACE_ARG_MUTATOR
        handle_pcap_error(handle);
    } else {
        // 9. Invoke pcap_setfilter
        if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
            handle_pcap_error(handle);
        }
        // Free the compiled program
        free(fp.bf_insns);
    }

    // 8. Invoke pcap_geterr
    char *err3 = pcap_geterr(handle);

    // 10. Invoke pcap_geterr again
    char *err4 = pcap_geterr(handle);

    // 11. Finally, invoke pcap_close
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function pcap_close with pcap_breakloop
    pcap_breakloop(handle);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

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
