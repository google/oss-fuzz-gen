#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsIOHANDLER *ioHandler;
    cmsHPROFILE profile;

    // Initialize the LCMS context
    context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a memory-based IO handler using the provided data
    // The function cmsOpenIOhandlerFromMem requires an additional argument for AccessMode
    ioHandler = cmsOpenIOhandlerFromMem(context, (void *)data, size, "r");
    if (ioHandler == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    profile = cmsOpenProfileFromIOhandlerTHR(context, ioHandler);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    // Ensure the IO handler is not used after being closed
    // Remove the call to cmsCloseIOhandler as it is handled internally by cmsOpenProfileFromIOhandlerTHR
    // cmsCloseIOhandler(ioHandler);
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
