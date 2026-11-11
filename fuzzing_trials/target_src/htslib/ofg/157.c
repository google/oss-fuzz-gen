#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Function-under-test declaration
uint32_t bam_auxB_len(const uint8_t *data);

int LLVMFuzzerTestOneInput_157(const uint8_t *data, size_t size) {
    // Ensure the data is not NULL and has at least one byte
    if (data == NULL || size == 0) {
        return 0;
    }

    // Call the function-under-test with the provided data
    uint32_t length = bam_auxB_len(data);

    // Optionally, print the result for debugging purposes
    // printf("Length: %u\n", length);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_157(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
