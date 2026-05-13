#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Initialize a cmsContext with a non-NULL value.
    cmsContext context = cmsCreateContext(NULL, NULL);
    
    // Use the input data to open a color profile from memory.
    cmsHPROFILE profile = cmsOpenProfileFromMemTHR(context, data, size);
    
    // If the profile was successfully created, perform some operations.
    if (profile != NULL) {
        // Example operation: Get the profile version.
        cmsGetProfileVersion(profile);
        
        // Close the profile after use.
        cmsCloseProfile(profile);
    }
    
    // Clean up the context after use.
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_101(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
