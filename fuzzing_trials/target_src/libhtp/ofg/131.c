#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void bstr_util_mem_trim(unsigned char **data, size_t *size);

int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    unsigned char *mutable_data;
    size_t mutable_size;

    // Allocate memory for mutable_data and copy the input data
    mutable_data = (unsigned char *)malloc(size);
    if (mutable_data == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(mutable_data, data, size);

    // Set mutable_size to the input size
    mutable_size = size;

    // Call the function-under-test
    bstr_util_mem_trim(&mutable_data, &mutable_size);

    // Free the allocated memory
    free(mutable_data);

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

    LLVMFuzzerTestOneInput_131(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
