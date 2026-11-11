#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const cmsCIEXYZ *d50_xyz = cmsD50_XYZ();

    // Use the returned pointer in some way to ensure the function is executed
    // Here, we just access the fields to simulate usage
    if (d50_xyz != NULL) {
        volatile double x = d50_xyz->X;
        volatile double y = d50_xyz->Y;
        volatile double z = d50_xyz->Z;

        // Use the variables to prevent optimization out
        (void)x;
        (void)y;
        (void)z;
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

    LLVMFuzzerTestOneInput_50(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
