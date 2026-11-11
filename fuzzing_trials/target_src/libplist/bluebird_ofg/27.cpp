#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    plist_t plist = NULL;
    char *bin_data = NULL;
    uint32_t bin_size = 0;
    plist_format_t format = PLIST_FORMAT_BINARY; // Add a default format

    // Create a plist from the input data
    plist_from_memory((const char*)data, size, &plist, &format);

    // Call the function-under-test

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from plist_from_memory to plist_int_val_compare
    uint32_t ret_plist_array_get_item_index_stdbx = plist_array_get_item_index(0);
    if (ret_plist_array_get_item_index_stdbx < 0){
    	return 0;
    }
    int ret_plist_int_val_compare_ozahn = plist_int_val_compare(plist, (int64_t )ret_plist_array_get_item_index_stdbx);
    if (ret_plist_int_val_compare_ozahn < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    plist_err_t result = plist_to_bin(plist, &bin_data, &bin_size);

    // Clean up
    if (bin_data != NULL) {
        free(bin_data);
    }
    if (plist != NULL) {
        plist_free(plist);
    }

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
