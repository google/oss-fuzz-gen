#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_300(const uint8_t *data, size_t size) {
    // Initialize memory context
    cmsContext contextID = cmsCreateContext(NULL, NULL);

    // Create a dummy profile
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();

    // Create a memory-based IO handler with read access
    cmsIOHANDLER *ioHandler = cmsOpenIOhandlerFromMem(contextID, (void *)data, size, "r");

    // Check if IO handler was created successfully
    if (ioHandler == NULL) {
        cmsCloseProfile(hProfile);
        cmsDeleteContext(contextID);
        return 0;
    }

    // Call the function under test
    cmsUInt32Number result = cmsSaveProfileToIOhandler(hProfile, ioHandler);

    // Clean up
    cmsCloseIOhandler(ioHandler);
    cmsCloseProfile(hProfile);
    cmsDeleteContext(contextID);

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

    LLVMFuzzerTestOneInput_300(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
