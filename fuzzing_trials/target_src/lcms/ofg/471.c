#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_471(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two cmsTagSignature values
    if (size < 2 * sizeof(cmsTagSignature)) {
        return 0;
    }

    // Initialize a memory context
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a dummy profile for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Extract two cmsTagSignature values from the input data
    cmsTagSignature sig1 = *(cmsTagSignature *)data;
    cmsTagSignature sig2 = *(cmsTagSignature *)(data + sizeof(cmsTagSignature));

    // Call the function under test
    cmsBool result = cmsLinkTag(hProfile, sig1, sig2);

    // Clean up
    cmsCloseProfile(hProfile);
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

    LLVMFuzzerTestOneInput_471(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
