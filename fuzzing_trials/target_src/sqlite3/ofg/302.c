#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_302(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer value from the input data
    int allocation_size = *(const int *)data;

    // Ensure the allocation size is positive to maximize fuzzing result
    if (allocation_size <= 0) {
        return 0;
    }

    // Call the function-under-test
    void *result = sqlite3_malloc(allocation_size);

    // If the allocation was successful, free the allocated memory
    if (result != NULL) {
        sqlite3_free(result);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_302(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
