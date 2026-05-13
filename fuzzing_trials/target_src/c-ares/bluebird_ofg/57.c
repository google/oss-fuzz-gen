#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ares.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_queue_active_queries to ares_set_local_ip4
    // Ensure dataflow is valid (i.e., non-null)
    if (!channel) {
    	return 0;
    }
    int ret_ares_init_tewmk = ares_init(&channel);
    if (ret_ares_init_tewmk < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!channel) {
    	return 0;
    }
    ares_set_local_ip4(channel, (unsigned int )ret_ares_queue_active_queries_znxjt);
    // End mutation: Producer.APPEND_MUTATOR
    
    char ret_ares_get_servers_csv_aajno = ares_get_servers_csv(channel);
    char ret_ares_inet_ntop_qwjlm = ares_inet_ntop((int )ret_ares_queue_active_queries_znxjt, (void *)&options, &ret_ares_get_servers_csv_aajno, 0);
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
