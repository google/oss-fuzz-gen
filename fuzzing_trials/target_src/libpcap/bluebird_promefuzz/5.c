#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap/pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERRBUF_SIZE PCAP_ERRBUF_SIZE

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *fp = fopen("./dummy_file", "wb");
    if (fp != NULL) {
        fwrite(Data, 1, Size, fp);
        fclose(fp);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    char errbuf[ERRBUF_SIZE];
    memset(errbuf, 0, ERRBUF_SIZE);

    // Invoke pcap_strerror
    const char *error_message = pcap_strerror(Data[0]);
    if (error_message == NULL) {
        return 0;
    }

    // Write data to a dummy file for pcap_open_offline
    write_dummy_file(Data, Size);

    // Invoke pcap_open_offline
    pcap_t *pcap_handle = pcap_open_offline("./dummy_file", errbuf);
    if (pcap_handle == NULL) {
        return 0;
    }

    // Prepare a null-terminated string for pcap_datalink_name_to_val

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from pcap_open_offline to pcap_getnonblock
    // Ensure dataflow is valid (i.e., non-null)
    if (!pcap_handle) {
    	return 0;
    }
    FILE* ret_pcap_file_retns = pcap_file(pcap_handle);
    if (ret_pcap_file_retns == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!pcap_handle) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!errbuf) {
    	return 0;
    }
    int ret_pcap_getnonblock_cndgj = pcap_getnonblock(pcap_handle, errbuf);
    if (ret_pcap_getnonblock_cndgj < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from pcap_getnonblock to pcap_dump_open_append
    // Ensure dataflow is valid (i.e., non-null)
    if (!pcap_handle) {
    	return 0;
    }
    int ret_pcap_can_set_rfmon_koqzu = pcap_can_set_rfmon(pcap_handle);
    if (ret_pcap_can_set_rfmon_koqzu < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!pcap_handle) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!errbuf) {
    	return 0;
    }
    pcap_dumper_t* ret_pcap_dump_open_append_tqfao = pcap_dump_open_append(pcap_handle, errbuf);
    if (ret_pcap_dump_open_append_tqfao == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    char dlt_name[Size + 1];
    memcpy(dlt_name, Data, Size);
    dlt_name[Size] = '\0';

    // Invoke pcap_datalink_name_to_val
    int dlt_val = pcap_datalink_name_to_val(dlt_name);

    // Invoke pcap_open_dead
    pcap_t *dead_handle = pcap_open_dead(dlt_val, 65535);
    if (dead_handle == NULL) {
        pcap_close(pcap_handle);
        return 0;
    }

    // Prepare a BPF program structure
    struct bpf_program fp;
    memset(&fp, 0, sizeof(fp));

    // Ensure the input buffer is null-terminated for pcap_compile
    char filter_exp[Size + 1];
    memcpy(filter_exp, Data, Size);
    filter_exp[Size] = '\0';

    // Invoke pcap_compile
    if (pcap_compile(dead_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == 0) {
        // Free the allocated memory for the BPF program
        if (fp.bf_insns != NULL) {
            free(fp.bf_insns);
        }
    }

    // Clean up
    pcap_close(pcap_handle);
    pcap_close(dead_handle);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
