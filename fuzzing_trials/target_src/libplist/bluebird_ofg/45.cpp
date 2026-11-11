#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for meaningful input
    if (size < 2) {
        return 0;
    }

    // Create a plist object
    plist_t plist = plist_new_string("example");

    // Create a null-terminated string from the input data
    char *input_string = (char *)malloc(size + 1);
    if (input_string == NULL) {
        plist_free(plist);
        return 0;
    }
    memcpy(input_string, data, size);
    input_string[size] = '\0';

    // Call the function-under-test
    int result = plist_string_val_compare(plist, input_string);

    // Clean up
    free(input_string);
    plist_free(plist);

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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
