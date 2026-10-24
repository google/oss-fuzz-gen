#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include "lcms2.h"

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    cmsHPROFILE handle;
    cmsCIELab cielab;

    // Ensure the data size is sufficient to fill a cmsCIELab structure
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize cmsCIELab with data from the input
    memcpy(&cielab, data, sizeof(cmsCIELab));

    // Ensure there is enough data left for a valid profile after cmsCIELab
    if (size < sizeof(cmsCIELab) + sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Initialize cmsHPROFILE (assuming a profile handle for the sake of example)
    handle = cmsOpenProfileFromMem(data + sizeof(cmsCIELab), size - sizeof(cmsCIELab));
    if (handle == NULL) {
        return 0; // If the profile cannot be opened, exit early
    }

    // Validate the profile to ensure it's not corrupted
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of cmsIsIntentSupported
    if (!cmsIsIntentSupported(handle, INTENT_PERCEPTUAL, PT_Yxy)) {
    // End mutation: Producer.REPLACE_ARG_MUTATOR
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function cmsCloseProfile with cmsMD5computeID
        cmsMD5computeID(handle);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsGDBCheckPoint(handle, &cielab);

    // Clean up
    cmsCloseProfile(handle);

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

    LLVMFuzzerTestOneInput_110(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
