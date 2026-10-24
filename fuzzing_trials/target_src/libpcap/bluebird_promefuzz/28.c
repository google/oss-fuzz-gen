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
#include <stdio.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    pcap_t *pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap_handle) {
        return 0;
    }

    struct bpf_program fp;
    memset(&fp, 0, sizeof(fp));

    char *filter_expr = (char *)malloc(Size + 1);
    if (!filter_expr) {
        pcap_close(pcap_handle);
        return 0;
    }

    memcpy(filter_expr, Data, Size);
    filter_expr[Size] = '\0';

    bpf_u_int32 netmask = 0xffffff00;
    int compile_result = pcap_compile(pcap_handle, &fp, filter_expr, 0, netmask);
    if (compile_result == PCAP_ERROR) {
        pcap_geterr(pcap_handle);
    }

    if (compile_result == 0) {
        int setfilter_result = pcap_setfilter(pcap_handle, &fp);
        if (setfilter_result == PCAP_ERROR) {
            pcap_geterr(pcap_handle);
        }
    
        // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from pcap_setfilter to pcap_list_datalinks using the plateau pool
        int *datalinks;
        // Ensure dataflow is valid (i.e., non-null)
        if (!pcap_handle) {
        	return 0;
        }
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function pcap_list_datalinks with pcap_list_tstamp_types
        int ret_pcap_list_datalinks_xshzn = pcap_list_tstamp_types(pcap_handle, &datalinks);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
        if (ret_pcap_list_datalinks_xshzn < 0){
        	return 0;
        }
        // End mutation: Producer.SPLICE_MUTATOR
        
}

    free(fp.bf_insns);

    write_dummy_file(Data, Size);
    pcap_dumper_t *dumper = pcap_dump_open(pcap_handle, "./dummy_file");
    if (!dumper) {
        pcap_geterr(pcap_handle);
    }

    pcap_datalink(pcap_handle);

    free(filter_expr);
    if (dumper) {
        pcap_dump_close(dumper);
    }
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
