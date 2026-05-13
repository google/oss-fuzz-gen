#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_236(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    cmsJCh jch;
    cmsCIEXYZ xyz;

    // Initialize the cmsJCh structure with some values
    jch.J = size > 0 ? data[0] : 50.0; // Luminance
    jch.C = size > 1 ? data[1] : 50.0; // Chroma
    jch.h = size > 2 ? data[2] : 50.0; // Hue

    // Create a viewing conditions structure
    cmsViewingConditions vc;
    cmsCIEXYZ D_value = {0.95047, 1.00000, 1.08883}; // D65 white point
    cmsCIEXYZ whitePoint = {0.95047, 1.00000, 1.08883}; // D65 white point
    cmsCIEXYZ background = {0.34567, 0.35850, 0.29583}; // typical background
    cmsFloat64Number surround = 2.0; // typical surround
    cmsFloat64Number adaptation = 1.0; // full adaptation

    // Initialize the viewing conditions
    vc.whitePoint = whitePoint;
    vc.Yb = background.Y; // Using the Y component of background as Yb
    vc.La = adaptation; // Using adaptation as La
    vc.surround = (cmsUInt32Number)surround; // Cast surround to cmsUInt32Number
    vc.D_value = D_value.Y; // Using the Y component of D_value as D_value

    // Create a handle using cmsCIECAM02Init
    handle = cmsCIECAM02Init(NULL, &vc);

    if (handle != NULL) {
        // Call the function-under-test
        cmsCIECAM02Reverse(handle, &jch, &xyz);

        // Clean up the handle
        cmsCIECAM02Done(handle);
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

    LLVMFuzzerTestOneInput_236(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
