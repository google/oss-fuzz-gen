#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    char *json_data;
    plist_t plist;
    plist_err_t err;

    // Ensure the input size is not zero to avoid unnecessary processing
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the JSON data and ensure it's null-terminated
    json_data = (char *)malloc(size + 1);
    if (json_data == NULL) {
        return 0;
    }

    // Copy the input data to the JSON buffer
    memcpy(json_data, data, size);
    json_data[size] = '\0'; // Null-terminate the string

    // Initialize the plist
    plist = NULL;

    // Call the function-under-test
    err = plist_from_json(json_data, (uint32_t)size, &plist);

    // Clean up
    free(json_data);
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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
