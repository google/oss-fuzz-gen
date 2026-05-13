#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "libdwarf.h"  // Ensure to include the appropriate header for dwarf_get_TAG_name

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    unsigned int tag;
    const char *name = NULL;

    if (size < sizeof(unsigned int)) {
        return 0; // Not enough data to extract an unsigned int
    }

    // Extract an unsigned int from the data
    tag = *(const unsigned int *)data;

    // Call the function-under-test
    int result = dwarf_get_TAG_name(tag, &name);

    // Optionally, you can use the result and name for further checks or logging
    // For example:
    // if (result == 0 && name != NULL) {
    //     printf("TAG: %u, Name: %s\n", tag, name);
    // }

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
