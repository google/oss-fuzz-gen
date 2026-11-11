#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_410(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a profile
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsOpenProfileFromMem((const void *)data, (cmsUInt32Number)size);

    // Check if the profile was successfully created
    if (profile != NULL) {
        // Close the profile to avoid memory leaks
        cmsCloseProfile(profile);
    }

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

    LLVMFuzzerTestOneInput_410(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
