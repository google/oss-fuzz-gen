#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_368(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    cmsViewingConditions viewingConditions;

    // Initialize the viewing conditions with some default values
    viewingConditions.D_value = 0.5;
    viewingConditions.surround = 0; // Corrected conversion issue
    viewingConditions.Yb = 20.0; // Added Yb value
    viewingConditions.La = 318.31; // Added La value
    viewingConditions.whitePoint.X = 0.95047;
    viewingConditions.whitePoint.Y = 1.0;
    viewingConditions.whitePoint.Z = 1.08883;

    // Initialize the handle using a non-NULL value
    handle = cmsCIECAM02Init(NULL, &viewingConditions);
    if (handle == NULL) {
        return 0; // Exit if initialization fails
    }

    // Call the function-under-test
    cmsCIECAM02Done(handle);

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

    LLVMFuzzerTestOneInput_368(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
