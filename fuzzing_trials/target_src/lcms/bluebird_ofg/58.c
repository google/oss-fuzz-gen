#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIEXYZ) * 3) {
        // Not enough data to fill all cmsCIEXYZ structures
        return 0;
    }

    // Initialize cmsCIEXYZ structures
    cmsCIEXYZ source;
    cmsCIEXYZ whitePoint;
    cmsCIEXYZ illuminant;
    cmsCIEXYZ result;

    // Copy data into cmsCIEXYZ structures
    memcpy(&source, data, sizeof(cmsCIEXYZ));
    memcpy(&whitePoint, data + sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));
    memcpy(&illuminant, data + 2 * sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));

    // Call the function-under-test
    cmsBool success = cmsAdaptToIlluminant(&result, &source, &whitePoint, &illuminant);

    // Use the result to avoid compiler optimizations removing the call
    if (success) {
        // Do something with result if needed
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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
