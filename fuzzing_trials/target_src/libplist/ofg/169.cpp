#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    // Function signature to be fuzzed
    int plist_string_val_contains(plist_t plist, const char *str);
}

extern "C" int LLVMFuzzerTestOneInput_169(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    // Create a plist object with a string derived from the input data
    char *plistString = (char *)malloc(size + 1);
    if (!plistString) {
        return 0;
    }
    memcpy(plistString, data, size);
    plistString[size] = '\0';

    plist_t plist = plist_new_string(plistString);

    // Ensure the data is null-terminated for use as a string
    char *inputString = (char *)malloc(size + 1);
    if (!inputString) {
        plist_free(plist);
        free(plistString);
        return 0;
    }
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Call the function-under-test
    int result = plist_string_val_contains(plist, inputString);

    // Clean up
    free(inputString);
    plist_free(plist);
    free(plistString);

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

    LLVMFuzzerTestOneInput_169(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
