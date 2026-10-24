#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_301(const uint8_t *data, size_t size) {
    cmsHPROFILE hProfile = NULL;
    cmsIOHANDLER *ioHandler = NULL;
    cmsContext context = NULL;
    cmsUInt32Number result = 0;

    if (size < 1) {
        return 0;
    }

    // Create a memory-based IO handler
    // Added the missing 'AccessMode' argument, using "r" for read mode
    ioHandler = cmsOpenIOhandlerFromMem(context, (void*)data, size, "r");
    if (ioHandler == NULL) {
        return 0;
    }

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        cmsCloseIOhandler(ioHandler);
        return 0;
    }

    // Call the function-under-test
    result = cmsSaveProfileToIOhandler(hProfile, ioHandler);

    // Clean up
    cmsCloseProfile(hProfile);
    cmsCloseIOhandler(ioHandler);

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

    LLVMFuzzerTestOneInput_301(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
