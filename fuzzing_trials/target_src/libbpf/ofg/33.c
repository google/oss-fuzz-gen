#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

// Function-under-test
int libbpf_strerror(int err, char *buf, size_t size);

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure there is enough data to use for the parameters
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Extract an integer error code from the data
    int err = *(int *)data;

    // Prepare a buffer for the error message
    size_t buf_size = size - sizeof(int);
    char buf[buf_size];
    memset(buf, 0, buf_size);

    // Call the function-under-test
    libbpf_strerror(err, buf, buf_size);

    // Optionally, print the error message for debugging
    // printf("Error message: %s\n", buf);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
