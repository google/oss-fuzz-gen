#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

// Remove 'extern "C"' as it is not needed in C code
int LLVMFuzzerTestOneInput_436(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIELab) + 3 * sizeof(double)) {
        return 0;
    }

    cmsCIELab lab;
    double a, b, c, d;

    // Initialize cmsCIELab structure
    lab.L = (double)data[0];
    lab.a = (double)data[1];
    lab.b = (double)data[2];

    // Extract doubles from the input data
    size_t offset = sizeof(cmsCIELab);
    a = *(double *)(data + offset);
    b = *(double *)(data + offset + sizeof(double));
    c = *(double *)(data + offset + 2 * sizeof(double));
    d = *(double *)(data + offset + 3 * sizeof(double));

    // Call the function-under-test
    cmsBool result = cmsDesaturateLab(&lab, a, b, c, d);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result) {
        // Do something if needed
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_436(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
