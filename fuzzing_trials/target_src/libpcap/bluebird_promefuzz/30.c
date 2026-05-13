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

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
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
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 3 of pcap_compile
    int compile_result = pcap_compile(pcap_handle, &fp, filter_expr, 64, netmask);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (compile_result == PCAP_ERROR) {
        pcap_geterr(pcap_handle);
    }

    if (compile_result == 0) {
        int setfilter_result = pcap_setfilter(pcap_handle, &fp);
        if (setfilter_result == PCAP_ERROR) {
            pcap_geterr(pcap_handle);
        }
    }

    free(fp.bf_insns);

    write_dummy_file(Data, Size);
    pcap_dumper_t *dumper = pcap_dump_open(pcap_handle, "./dummy_file");
    if (!dumper) {
        pcap_geterr(pcap_handle);
    }


    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from pcap_dump_open to pcap_set_datalink using the plateau pool
    char dlt_name[16];
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function pcap_datalink_name_to_val with pcap_tstamp_type_name_to_val
    int dlt_val = pcap_tstamp_type_name_to_val(dlt_name);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    // Ensure dataflow is valid (i.e., non-null)
    if (!pcap_handle) {
    	return 0;
    }
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of pcap_set_datalink
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function pcap_set_datalink with pcap_set_tstamp_precision
    int ret_pcap_set_datalink_dsmjb = pcap_set_tstamp_precision(pcap_handle, 64);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (ret_pcap_set_datalink_dsmjb < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
