#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_400(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const cmsCIExyY *d50_xyY = cmsD50_xyY();

    // Use the returned value to ensure the function is executed
    // Here we just perform a simple check to ensure the pointer is not NULL
    if (d50_xyY != NULL) {
        // Access the fields of cmsCIExyY to ensure they are valid
        volatile double x = d50_xyY->x;
        volatile double y = d50_xyY->y;
        volatile double Y = d50_xyY->Y;

        // Use the accessed values to avoid compiler optimizations
        (void)x;
        (void)y;
        (void)Y;
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

    LLVMFuzzerTestOneInput_400(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
