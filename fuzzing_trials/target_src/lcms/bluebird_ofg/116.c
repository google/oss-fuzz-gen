#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to split into meaningful parts
    if (size < 4) {
        return 0;
    }

    // Allocate and initialize a cmsMLU object
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);

    // Split the input data into three parts for the UTF-8 strings
    size_t part_size = size / 3;
    size_t remainder = size % 3;

    const char *string1 = (const char *)data;
    const char *string2 = (const char *)(data + part_size);
    const char *string3 = (const char *)(data + 2 * part_size);

    // Null-terminate the strings
    char *utf8String1 = (char *)malloc(part_size + 1);
    char *utf8String2 = (char *)malloc(part_size + 1 + (remainder > 0 ? 1 : 0));
    char *utf8String3 = (char *)malloc(part_size + 1 + (remainder > 1 ? 1 : 0));

    memcpy(utf8String1, string1, part_size);
    utf8String1[part_size] = '\0';

    memcpy(utf8String2, string2, part_size + (remainder > 0 ? 1 : 0));
    utf8String2[part_size + (remainder > 0 ? 1 : 0)] = '\0';

    memcpy(utf8String3, string3, part_size + (remainder > 1 ? 1 : 0));
    utf8String3[part_size + (remainder > 1 ? 1 : 0)] = '\0';

    // Call the function-under-test
    cmsMLUsetUTF8(mlu, utf8String1, utf8String2, utf8String3);

    // Clean up
    cmsMLUfree(mlu);
    free(utf8String1);
    free(utf8String2);
    free(utf8String3);

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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
