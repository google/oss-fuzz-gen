#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include string.h for memcpy
#include "ares.h"

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    /* Ensure there's enough data to allocate */
    if (size < sizeof(void*)) {
        return 0;
    }

    // Allocate memory and copy data into it
    void *dataptr = malloc(size);
    if (dataptr == NULL) {
        return 0;
    }
    memcpy(dataptr, data, size);

    // Call the function-under-test
    ares_free_data(dataptr);

    // No need to free dataptr as ares_free_data is expected to handle it
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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
