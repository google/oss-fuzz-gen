#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ares.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    /* Initialize the ares library */
    ares_library_init(ARES_LIB_INIT_ALL);

    /* Create a channel */
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;
    int status = ares_init_options(&channel, &options, optmask);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    /* Ensure the data is null-terminated for use as a CSV string */
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from ares_set_servers_ports_csv to ares_gethostbyname_file
    // Ensure dataflow is valid (i.e., non-null)
    if (!channel) {
    	return 0;
    }
    int ret_ares_init_qiwfy = ares_init(&channel);
    if (ret_ares_init_qiwfy < 0){
    	return 0;
    }
    unsigned short ret_ares_dns_record_get_flags_yfmcn = ares_dns_record_get_flags(NULL);
    if (ret_ares_dns_record_get_flags_yfmcn < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!channel) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!csv) {
    	return 0;
    }
    int ret_ares_gethostbyname_file_rpijf = ares_gethostbyname_file(channel, csv, (int )ret_ares_dns_record_get_flags_yfmcn, NULL);
    if (ret_ares_gethostbyname_file_rpijf < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
