#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    plist_t plist;
    uint64_t length = 0;
    
    // Create a plist from the input data
    plist_from_bin((const char*)data, size, &plist);
    
    // Check if plist creation was successful
    if (plist != NULL) {
        // Call the function-under-test
        const char *data_ptr = plist_get_data_ptr(plist, &length);
        
        // Optionally, use the returned data_ptr and length for further processing
        if (data_ptr != NULL) {
            // For demonstration purposes, we'll just print the length
            printf("Data length: %llu\n", (unsigned long long)length);
        }
        
        // Free the plist to avoid memory leaks
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
