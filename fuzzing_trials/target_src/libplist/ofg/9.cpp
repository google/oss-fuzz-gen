#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    // Function signature from the project
    plist_err_t plist_from_openstep(const char *data, uint32_t length, plist_t *plist);
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Ensure the input size is not zero
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the input data to be passed as a string
    char *input_data = (char *)malloc(size + 1);
    if (input_data == NULL) {
        return 0;
    }

    // Copy the input data and ensure it is null-terminated
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Initialize a plist_t variable
    plist_t plist = NULL;

    // Call the function-under-test
    plist_err_t result = plist_from_openstep(input_data, (uint32_t)size, &plist);

    // Clean up
    if (plist != NULL) {
        plist_free(plist);
    }
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
