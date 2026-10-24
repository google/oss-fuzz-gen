#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    int error_code;

    // Ensure that size is at least 4 bytes to safely read an int
    if (size < sizeof(int)) {
        return 0;
    }

    // Interpret the first 4 bytes of data as an int
    error_code = *(int*)data;

    // Call the function-under-test
    const char *error_message = zError(error_code);

    // Use the error_message in some way to ensure it is not optimized away
    if (error_message != NULL) {
        // Just a dummy operation to use error_message
        volatile const char *dummy = error_message;
        (void)dummy;
    }

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

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
