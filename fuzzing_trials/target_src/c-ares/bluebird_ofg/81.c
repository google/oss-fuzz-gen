#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ares.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    /* Initialize the ares library */
    ares_library_init(ARES_LIB_INIT_ALL);

    /* Create a channel */
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of ares_init_options
    int status = ares_init_options(&channel, &options, ARES_NI_SCTP);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (status != ARES_SUCCESS) {
        return 0;
    }

    /* Ensure the data is null-terminated for use as a CSV string */

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_init_options to ares_inet_ntop
    size_t ret_ares_queue_active_queries_znxjt = ares_queue_active_queries(NULL);
    if (ret_ares_queue_active_queries_znxjt < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!channel) {
    	return 0;
    }
    char ret_ares_get_servers_csv_aajno = ares_get_servers_csv(channel);
    char ret_ares_inet_ntop_qwjlm = ares_inet_ntop((int )ret_ares_queue_active_queries_znxjt, (void *)&options, &ret_ares_get_servers_csv_aajno, 0);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_inet_ntop to ares_expand_string
    char ret_ares_strerror_aowrp = ares_strerror(ARES_OPT_UDP_MAX_QUERIES);
    unsigned short ret_ares_dns_record_get_flags_lpsoq = ares_dns_record_get_flags(&options);
    if (ret_ares_dns_record_get_flags_lpsoq < 0){
    	return 0;
    }
    size_t ret_ares_dns_record_query_cnt_kvwtn = ares_dns_record_query_cnt(NULL);
    if (ret_ares_dns_record_query_cnt_kvwtn < 0){
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_dns_record_query_cnt to ares_parse_naptr_reply
    struct ares_addr hxrsxwrs;
    memset(&hxrsxwrs, 0, sizeof(hxrsxwrs));
    char ret_ares_dns_addr_to_ptr_wtpuh = ares_dns_addr_to_ptr(&hxrsxwrs);
    int ret_ares_parse_naptr_reply_osdim = ares_parse_naptr_reply((unsigned char *)&ret_ares_dns_addr_to_ptr_wtpuh, (int )ret_ares_dns_record_query_cnt_kvwtn, &options);
    if (ret_ares_parse_naptr_reply_osdim < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int ret_ares_expand_string_tjtnu = ares_expand_string((unsigned char *)&ret_ares_strerror_aowrp, &options, (int )ret_ares_dns_record_get_flags_lpsoq, &options, (long *)&ret_ares_dns_record_query_cnt_kvwtn);
    if (ret_ares_expand_string_tjtnu < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_expand_string to ares_parse_uri_reply

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_expand_string to ares_dns_rr_get_keys
    ares_dns_rec_type_t ret_ares_dns_rr_get_type_vtcac = ares_dns_rr_get_type(&options);
    ares_dns_rr_key_t ret_ares_dns_rr_get_keys_eyixm = ares_dns_rr_get_keys(ret_ares_dns_rr_get_type_vtcac, &ret_ares_dns_record_query_cnt_kvwtn);
    // End mutation: Producer.APPEND_MUTATOR
    
    char ret_ares_dns_rcode_tostr_tkgwc = ares_dns_rcode_tostr(&ret_ares_strerror_aowrp);
    int ret_ares_parse_uri_reply_ersws = ares_parse_uri_reply((unsigned char *)&ret_ares_dns_rcode_tostr_tkgwc, &ret_ares_dns_record_query_cnt_kvwtn, &options);
    if (ret_ares_parse_uri_reply_ersws < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    char *csv = (char *)malloc(size + 1);
    if (!csv) {
        ares_destroy(channel);
        return 0;
    }
    memcpy(csv, data, size);
    csv[size] = '\0';

    /* Call the function-under-test */
    ares_set_servers_ports_csv(channel, csv);

    /* Clean up */
    free(csv);
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
