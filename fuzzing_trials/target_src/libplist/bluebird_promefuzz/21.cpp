#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t)) {
        return 0;
    }

    // Extract an int64_t value from the input data
    int64_t int_value;
    memcpy(&int_value, Data, sizeof(int64_t));

    // Create a new plist node of type PLIST_INT with the extracted integer value
    plist_t node = plist_new_int(int_value);
    if (!node) {
        return 0;
    }

    // Set the node's value to another integer value
    plist_set_int_val(node, int_value);

    // Compare the node's value with another integer
    int compare_result = plist_int_val_compare(node, int_value);

    // Compare the node's value with an unsigned integer
    uint64_t uint_value = static_cast<uint64_t>(int_value);
    int uint_compare_result = plist_uint_val_compare(node, uint_value);

    // Retrieve the signed integer value from the node
    int64_t retrieved_value;
    plist_get_int_val(node, &retrieved_value);

    // Check if the node's value is negative
    int is_negative = plist_int_val_is_negative(node);

    // Clean up
    plist_free(node);

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
