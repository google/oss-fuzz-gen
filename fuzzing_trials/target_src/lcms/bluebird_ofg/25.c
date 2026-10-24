#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Ensure we have enough data to fill the structures
    if (size < sizeof(cmsCIEXYZ)) {
        return 0;
    }

    // Initialize the cmsHANDLE, in this case, we assume it is a context
    cmsHANDLE handle = cmsCreateContext(NULL, NULL);
    if (handle == NULL) {
        return 0;
    }

    // Prepare the cmsCIEXYZ input
    cmsCIEXYZ inputXYZ;
    memcpy(&inputXYZ, data, sizeof(cmsCIEXYZ));

    // Prepare the cmsJCh output
    cmsJCh outputJCh;

    // Initialize the cmsCIECAM02 structure
    cmsViewingConditions vc;
    memset(&vc, 0, sizeof(vc));
    vc.D_value = 1.0;
    vc.surround = 1; // Assuming surround is an integer value
    vc.La = 318.31;
    vc.Yb = 20.0;
    vc.whitePoint.X = 0.95047; // D65 standard illuminant
    vc.whitePoint.Y = 1.0;
    vc.whitePoint.Z = 1.08883;

    // Call the function-under-test
    cmsCIECAM02Forward(&vc, &inputXYZ, &outputJCh);

    // Clean up
    cmsDeleteContext(handle);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
