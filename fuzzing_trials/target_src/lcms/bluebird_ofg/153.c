#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for creating a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Initialize a cmsContext variable
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Use the input data to create a profile
    cmsHPROFILE profile = cmsOpenProfileFromMemTHR(context, data, size);

    // Perform operations on the profile if it's valid
    if (profile != NULL) {
        // Example operation: get profile info
        char info[256];
        cmsGetProfileInfoASCII(profile, cmsInfoDescription, "en", "US", info, sizeof(info));

        // Clean up
        cmsCloseProfile(profile);
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

    LLVMFuzzerTestOneInput_153(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
