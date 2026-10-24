#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    plist_t plist = NULL;
    char *bin_data = NULL;
    uint32_t bin_size = 0;
    plist_format_t format = PLIST_FORMAT_BINARY; // Add a default format

    // Create a plist from the input data
    plist_from_memory((const char*)data, size, &plist, &format);

    // Call the function-under-test
    plist_err_t result = plist_to_bin(plist, &bin_data, &bin_size);

    // Clean up
    if (bin_data != NULL) {
        free(bin_data);
    }
    if (plist != NULL) {
        plist_free(plist);
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from plist_to_bin to plist_dict_copy_int
    plist_t ret_plist_new_uid_dddlh = plist_new_uid(0);
    plist_t ret_plist_new_real_wlauu = plist_new_real(64);
    // Ensure dataflow is valid (i.e., non-null)
    if (!bin_data) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!bin_data) {
    	return 0;
    }
    plist_err_t ret_plist_dict_copy_int_oypkk = plist_dict_copy_int(ret_plist_new_uid_dddlh, ret_plist_new_real_wlauu, bin_data, bin_data);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
