#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to interpret as a double
    if (size < sizeof(double)) {
        return 0;
    }

    // Interpret the first sizeof(double) bytes of data as a double
    double input_double;
    memcpy(&input_double, data, sizeof(double));

    // Call the function-under-test
    ucl_object_t *result = ucl_object_fromdouble(input_double);

    // Clean up the result if necessary
    if (result != NULL) {
        ucl_object_unref(result);
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

    LLVMFuzzerTestOneInput_91(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
