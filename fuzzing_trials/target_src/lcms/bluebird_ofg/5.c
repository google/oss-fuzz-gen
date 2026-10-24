#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    cmsUInt32Number intent = 0; // Rendering intent
    cmsUInt32Number flags = 0; // Flags for the function
    void *buffer = malloc(1024); // Allocate a buffer for output
    cmsUInt32Number bufferSize = 1024; // Size of the buffer

    // Ensure the profile is valid before calling the function
    if (hProfile != NULL && buffer != NULL) {
        // Call the function-under-test
        cmsUInt32Number result = cmsGetPostScriptCRD(context, hProfile, intent, flags, buffer, bufferSize);
        
        // Optionally, use the result for further checks or logging
        (void)result; // Suppress unused variable warning
    }

    // Clean up
    if (hProfile != NULL) {
        cmsCloseProfile(hProfile);
    }
    if (buffer != NULL) {
        free(buffer);
    }
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
