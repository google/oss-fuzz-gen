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
#include <cstring>
#include <cstdlib>
#include <ctime>
#include "plist/plist.h"

static plist_t create_random_plist_data() {
    plist_t node = plist_new_data(nullptr, 0);
    uint64_t length = rand() % 256; // Random length between 0 and 255
    char *data = (char *)malloc(length);
    if (data) {
        for (uint64_t i = 0; i < length; ++i) {
            data[i] = rand() % 256; // Fill with random bytes
        }
        plist_set_data_val(node, data, length);
        free(data);
    }
    return node;
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    srand(time(0));

    // Create target and source dictionaries
    plist_t target_dict = plist_new_dict();
    plist_t source_dict = plist_new_dict();

    // Create a random PLIST_DATA node and add it to source_dict
    plist_t data_node = create_random_plist_data();
    plist_dict_set_item(source_dict, "source_key", data_node);

    // Use the first byte of Data as a key
    char key[2] = {static_cast<char>(Data[0]), '\0'};
    char alt_key[2] = {static_cast<char>(Data[0] + 1), '\0'};

    // Test plist_dict_copy_data
    plist_err_t result = plist_dict_copy_data(target_dict, source_dict, key, alt_key);
    if (result == PLIST_ERR_SUCCESS) {
        // If successful, test plist_data_val_compare_with_size
        uint64_t length;
        const char *data_ptr = plist_get_data_ptr(data_node, &length);
        if (data_ptr) {
            int cmp_result = plist_data_val_compare_with_size(data_node, Data, Size);
            (void)cmp_result; // Use the result to avoid unused variable warning
        }
    }

    // Test plist_data_val_compare
    int full_cmp_result = plist_data_val_compare(data_node, Data, Size);
    (void)full_cmp_result; // Use the result to avoid unused variable warning

    // Test plist_data_val_contains
    int contains_result = plist_data_val_contains(data_node, Data, Size);
    (void)contains_result; // Use the result to avoid unused variable warning

    // Clean up
    plist_free(target_dict);
    plist_free(source_dict);

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
