#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Add the fourth argument "r" for read mode
    cmsIOHANDLER *ioHandler = cmsOpenIOhandlerFromMem(context, (void *)data, (cmsUInt32Number)size, "r");
    if (ioHandler == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    cmsBool readOnly = TRUE; // or FALSE, try both
    cmsHPROFILE profile = cmsOpenProfileFromIOhandler2THR(context, ioHandler, readOnly);

    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    // Ensure the IO handler is closed only after the profile is closed
    // Remove cmsCloseIOhandler(ioHandler) as it should not be called explicitly
    // The profile management functions should handle it internally

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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
