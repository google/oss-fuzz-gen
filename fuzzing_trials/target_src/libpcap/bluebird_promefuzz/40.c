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

int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of pcap_open_dead
    pcap_t *pcap_handle = pcap_open_dead(Size, 65535);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
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
    }

    free(fp.bf_insns);

    write_dummy_file(Data, Size);
    pcap_dumper_t *dumper = pcap_dump_open(pcap_handle, "./dummy_file");
    if (!dumper) {
        pcap_geterr(pcap_handle);
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from pcap_dump_open to pcap_inject
    // Ensure dataflow is valid (i.e., non-null)
    if (!pcap_handle) {
    	return 0;
    }
    int ret_pcap_bufsize_xhgmw = pcap_bufsize(pcap_handle);
    if (ret_pcap_bufsize_xhgmw < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!dumper) {
    	return 0;
    }
    int64_t ret_pcap_dump_ftell64_zwqcu = pcap_dump_ftell64(dumper);
    if (ret_pcap_dump_ftell64_zwqcu < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!pcap_handle) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!dumper) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from pcap_dump_ftell64 to pcap_parsesrcstr
    char* ret_pcap_geterr_xrucm = pcap_geterr(NULL);
    if (ret_pcap_geterr_xrucm == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!pcap_handle) {
    	return 0;
    }
    char* ret_pcap_geterr_ghnpe = pcap_geterr(pcap_handle);
    if (ret_pcap_geterr_ghnpe == NULL){
    	return 0;
    }
    char* ret_pcap_geterr_utbqp = pcap_geterr(NULL);
    if (ret_pcap_geterr_utbqp == NULL){
    	return 0;
    }
    char* ret_pcap_lookupdev_qpytx = pcap_lookupdev(NULL);
    if (ret_pcap_lookupdev_qpytx == NULL){
    	return 0;
    }
    char ybzcbqoy[1024] = "xtrgd";
    char* ret_pcap_lookupdev_codan = pcap_lookupdev(ybzcbqoy);
    if (ret_pcap_lookupdev_codan == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_pcap_geterr_xrucm) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_pcap_geterr_ghnpe) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_pcap_geterr_utbqp) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_pcap_lookupdev_qpytx) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ybzcbqoy) {
    	return 0;
    }
    int ret_pcap_parsesrcstr_dyfqh = pcap_parsesrcstr(ret_pcap_geterr_xrucm, (int *)&ret_pcap_dump_ftell64_zwqcu, ret_pcap_geterr_ghnpe, ret_pcap_geterr_utbqp, ret_pcap_lookupdev_qpytx, ybzcbqoy);
    if (ret_pcap_parsesrcstr_dyfqh < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int ret_pcap_inject_yamkq = pcap_inject(pcap_handle, (const void *)dumper, (size_t )ret_pcap_dump_ftell64_zwqcu);
    if (ret_pcap_inject_yamkq < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
