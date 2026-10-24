#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create meaningful strings
    if (size < 2) return 0;

    // Initialize plist variables
    plist_t source_dict = plist_new_dict();
    plist_t dest_dict = plist_new_dict();

    // Create strings from the input data
    size_t key1_len = data[0] % size; // Ensure the length is within bounds
    size_t key2_len = (size - key1_len - 1) > 0 ? (size - key1_len - 1) : 1;

    char *key1 = static_cast<char*>(malloc(key1_len + 1));
    char *key2 = static_cast<char*>(malloc(key2_len + 1));

    if (!key1 || !key2) {
        free(key1);
        free(key2);
        plist_free(source_dict);
        plist_free(dest_dict);
        return 0;
    }

    memcpy(key1, data + 1, key1_len);
    memcpy(key2, data + 1 + key1_len, key2_len);

    key1[key1_len] = '\0';
    key2[key2_len] = '\0';

    // Call the function-under-test
    plist_dict_copy_int(source_dict, dest_dict, key1, key2);

    // Clean up
    free(key1);
    free(key2);
    plist_free(source_dict);
    plist_free(dest_dict);

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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
