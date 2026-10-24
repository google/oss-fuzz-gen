#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern "C" {
    #include "/src/liblouis/liblouis/liblouis.h"  // Correct path for the header file
}

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create two non-empty strings
    if (size < 2) return 0;

    // Find a split point for the two strings
    size_t split_point = size / 2;

    // Allocate memory for the two strings
    char *emphClass = new char[split_point + 1];
    char *typeform = new char[size - split_point + 1];

    // Copy data into the strings and null-terminate them
    memcpy(emphClass, data, split_point);
    emphClass[split_point] = '\0';

    memcpy(typeform, data + split_point, size - split_point);
    typeform[size - split_point] = '\0';

    // Call the function-under-test
    formtype result = lou_getTypeformForEmphClass(emphClass, typeform);

    // Clean up
    delete[] emphClass;
    delete[] typeform;

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
