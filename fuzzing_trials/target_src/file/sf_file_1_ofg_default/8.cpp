#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <magic.h>

extern "C" {
    // Include the function-under-test
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize a magic_set structure
    struct magic_set *mset = magic_open(MAGIC_NONE);
    if (mset == NULL) {
        return 0;
    }

    // Extract an integer from the data
    int descriptor = *(reinterpret_cast<const int*>(data));

    // Call the function-under-test
    const char *result = magic_descriptor(mset, descriptor);

    // Print the result for debugging purposes
    if (result != NULL) {
        printf("Magic descriptor result: %s\n", result);
    }

    // Clean up
    magic_close(mset);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
