#include <sys/stat.h>
#include <string.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *input_data = (char *)malloc(size + 1);
    if (!input_data) {
        return 0;
    }
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Initialize a plist_t variable
    plist_t plist = nullptr;

    // Call the function-under-test
    plist_err_t result = plist_from_bin(input_data, (uint32_t)size, &plist);

    // Clean up
    if (plist) {
        plist_free(plist);
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from plist_from_bin to plist_dict_copy_item
    plist_t ret_plist_new_uid_efhlm = plist_new_uid(64);
    plist_err_t ret_plist_dict_copy_item_iwnxm = plist_dict_copy_item(plist, ret_plist_new_uid_efhlm, (const char *)"w", (const char *)"w");
    // End mutation: Producer.APPEND_MUTATOR
    
    free(input_data);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
