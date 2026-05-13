#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <ucl.h>

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    if (size < sizeof(ucl_object_iter_t)) {
        return 0;
    }

    // Allocate memory for ucl_object_iter_t and copy data into it
    ucl_object_iter_t *iter = (ucl_object_iter_t *)malloc(sizeof(ucl_object_iter_t));
    if (iter == NULL) {
        return 0;
    }

    // Initialize the iterator with the input data
    memcpy(iter, data, sizeof(ucl_object_iter_t));

    // Call the function-under-test
    bool result = ucl_object_iter_chk_excpn(iter);

    // Clean up
    free(iter);

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

    LLVMFuzzerTestOneInput_124(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
