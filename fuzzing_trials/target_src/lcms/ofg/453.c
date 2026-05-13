#include <stdint.h>
#include <lcms2.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_453(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context = (cmsContext)0x1; // Dummy non-NULL context
    cmsPSResourceType resourceType = cmsPS_RESOURCE_CSA; // Example resource type
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size); // Create a profile from the input data
    cmsUInt32Number intent = 0; // Example intent
    cmsUInt32Number flags = 0; // Example flags

    // Initialize ioHandler using Little CMS function
    cmsIOHANDLER *ioHandler = cmsOpenIOhandlerFromNULL(context);

    // Check if profile creation was successful
    if (hProfile == NULL || ioHandler == NULL) {
        if (hProfile != NULL) {
            cmsCloseProfile(hProfile);
        }
        return 0; // Exit if profile creation failed or ioHandler initialization failed
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsGetPostScriptColorResource(context, resourceType, hProfile, intent, flags, ioHandler);

    // Clean up
    cmsCloseIOhandler(ioHandler); // Properly close the ioHandler
    cmsCloseProfile(hProfile);

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

    LLVMFuzzerTestOneInput_453(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
