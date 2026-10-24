#include <stdint.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_161(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract a ucl_type_t value
    if (size < sizeof(ucl_type_t)) {
        return 0;
    }

    // Extract a ucl_type_t from the input data
    ucl_type_t type = *(ucl_type_t *)data;

    // Call the function-under-test
    const char *result = ucl_object_type_to_string(type);

    // Use the result in some way to prevent the compiler from optimizing it away
    if (result != NULL) {
        // Just a dummy operation to use the result
        volatile const char *dummy = result;
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

    LLVMFuzzerTestOneInput_161(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
