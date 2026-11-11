#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_388(const uint8_t *data, size_t size) {
    // Ensure there is enough data to fill two cmsCIELab structures
    if (size < 2 * sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize two cmsCIELab structures from the input data
    cmsCIELab lab1;
    cmsCIELab lab2;

    // Copy data into the cmsCIELab structures
    memcpy(&lab1, data, sizeof(cmsCIELab));
    memcpy(&lab2, data + sizeof(cmsCIELab), sizeof(cmsCIELab));

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsBFDdeltaE(&lab1, &lab2);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)deltaE;

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

    LLVMFuzzerTestOneInput_388(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
