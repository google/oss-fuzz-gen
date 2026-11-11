#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to fill two cmsCIELab structures
    if (size < 2 * sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize two cmsCIELab structures using data from the input
    cmsCIELab Lab1;
    cmsCIELab Lab2;

    // Copy data into the cmsCIELab structures
    memcpy(&Lab1, data, sizeof(cmsCIELab));
    memcpy(&Lab2, data + sizeof(cmsCIELab), sizeof(cmsCIELab));

    // Call the function-under-test
    cmsFloat64Number deltaE = cmsCIE94DeltaE(&Lab1, &Lab2);

    // Print the result (optional, for debugging purposes)
    printf("Delta E: %f\n", deltaE);

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

    LLVMFuzzerTestOneInput_2(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
