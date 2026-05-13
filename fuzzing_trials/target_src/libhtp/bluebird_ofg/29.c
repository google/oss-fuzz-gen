#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htp/htp.h"

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from htp_connp_create to bstr_begins_with_mem
    bstr* ret_bstr_dup_c_geire = bstr_dup_c((const char *)"r");
    if (ret_bstr_dup_c_geire == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bstr_dup_c to bstr_add_c_noex
    char* ret_htp_get_version_fbiia = htp_get_version();
    if (ret_htp_get_version_fbiia == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bstr_dup_c_geire) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_htp_get_version_fbiia) {
    	return 0;
    }
    bstr* ret_bstr_add_c_noex_pqqpk = bstr_add_c_noex(ret_bstr_dup_c_geire, ret_htp_get_version_fbiia);
    if (ret_bstr_add_c_noex_pqqpk == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    size_t ret_htp_connp_req_data_consumed_bnwbk = htp_connp_req_data_consumed(connp);
    if (ret_htp_connp_req_data_consumed_bnwbk < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bstr_dup_c_geire) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }
    int ret_bstr_begins_with_mem_pkfwu = bstr_begins_with_mem(ret_bstr_dup_c_geire, (const void *)connp, ret_htp_connp_req_data_consumed_bnwbk);
    if (ret_bstr_begins_with_mem_pkfwu < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    htp_status_t status = htp_connp_req_data(connp, NULL, data, size);

    // Clean up
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
