#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htp/htp.h"

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Initialize the transaction object
    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) {
        return 0; // Exit if configuration creation fails
    }

    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg);
        return 0; // Exit if connection parser creation fails
    }

    // Ensure the data pointer is not NULL and size is non-zero
    if (data == NULL || size == 0) {
        htp_connp_destroy_all(connp);
        htp_config_destroy(cfg);
        return 0;
    }

    // Simulate a request by feeding the data to the connection parser
    htp_status_t status = htp_connp_req_data(connp, NULL, data, size);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from htp_connp_req_data to bstr_cmp_mem_nocase
    bstr rcytcfqh;
    memset(&rcytcfqh, 0, sizeof(rcytcfqh));
    bstr* ret_bstr_dup_uweyh = bstr_dup(&rcytcfqh);
    if (ret_bstr_dup_uweyh == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }
    size_t ret_htp_connp_req_data_consumed_vzvxp = htp_connp_req_data_consumed(connp);
    if (ret_htp_connp_req_data_consumed_vzvxp < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bstr_dup_uweyh) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }
    int ret_bstr_cmp_mem_nocase_cnccu = bstr_cmp_mem_nocase(ret_bstr_dup_uweyh, (const void *)connp, ret_htp_connp_req_data_consumed_vzvxp);
    if (ret_bstr_cmp_mem_nocase_cnccu < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    htp_connp_destroy_all(connp);
    htp_config_destroy(cfg);

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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
