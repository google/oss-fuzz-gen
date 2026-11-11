#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "htp/htp.h"
#include "htp/htp.h"
#include "htp/htp.h"
#include "/src/libhtp/htp/htp_connection_parser.h"

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) {
        return 0;
    }

    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg);
        return 0;
    }

    htp_connp_set_user_data(connp, (void *)Data);

    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);

    htp_connp_open(connp, "127.0.0.1", 80, "127.0.0.1", 8080, &timestamp);
    htp_connp_open(connp, "127.0.0.1", 80, "127.0.0.1", 8080, &timestamp);

    htp_connp_req_data(connp, &timestamp, Data, Size);
    htp_connp_req_data_consumed(connp);

    htp_connp_res_data(connp, &timestamp, Data, Size);
    htp_connp_res_data(connp, &timestamp, Data, Size);

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from htp_connp_res_data to htp_connp_req_data
    bstr* ret_bstr_alloc_jsarl = bstr_alloc(Size);
    if (ret_bstr_alloc_jsarl == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }
    size_t ret_htp_connp_res_data_consumed_uepdx = htp_connp_res_data_consumed(connp);
    if (ret_htp_connp_res_data_consumed_uepdx < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_bstr_alloc_jsarl) {
    	return 0;
    }
    int ret_htp_connp_req_data_hbhdr = htp_connp_req_data(connp, &timestamp, (const void *)ret_bstr_alloc_jsarl, ret_htp_connp_res_data_consumed_uepdx);
    if (ret_htp_connp_req_data_hbhdr < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    htp_connp_res_data_consumed(connp);


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from htp_connp_res_data_consumed to bstr_util_memdup_to_c
    // Ensure dataflow is valid (i.e., non-null)
    if (!connp) {
    	return 0;
    }
    char* ret_bstr_util_memdup_to_c_floah = bstr_util_memdup_to_c((const void *)connp, HTP_CONFIG_SHARED);
    if (ret_bstr_util_memdup_to_c_floah == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    htp_connp_req_data(connp, &timestamp, Data, Size);
    htp_connp_res_data(connp, &timestamp, Data, Size);

    htp_connp_close(connp, &timestamp);

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
