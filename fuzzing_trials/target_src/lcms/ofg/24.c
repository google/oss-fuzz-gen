#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    cmsHPROFILE profile;
    cmsFloat64Number version;

    // Ensure there's enough data to extract a cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Create a dummy profile for testing
    profile = cmsCreate_sRGBProfile();
    if (profile == NULL) {
        return 0;
    }

    // Extract a cmsFloat64Number from the input data
    version = *(const cmsFloat64Number *)data;

    // Call the function-under-test
    cmsSetProfileVersion(profile, version);

    // Clean up
    cmsCloseProfile(profile);

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

    LLVMFuzzerTestOneInput_24(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
