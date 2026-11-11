#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "htp/htp.h"

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
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
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function htp_connp_req_data with htp_connp_res_data
    htp_status_t status = htp_connp_res_data(connp, NULL, data, size);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from htp_connp_res_data to htp_tx_res_process_body_data
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }
    htp_tx_t* ret_htp_tx_create_bqqhs = htp_tx_create(connp);
    if (ret_htp_tx_create_bqqhs == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }
    size_t ret_htp_connp_res_data_consumed_ubmpd = htp_connp_res_data_consumed(connp);
    if (ret_htp_connp_res_data_consumed_ubmpd < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_htp_tx_create_bqqhs) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }
    htp_status_t ret_htp_tx_res_process_body_data_lagvo = htp_tx_res_process_body_data(ret_htp_tx_create_bqqhs, (const void *)connp, ret_htp_connp_res_data_consumed_ubmpd);
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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
