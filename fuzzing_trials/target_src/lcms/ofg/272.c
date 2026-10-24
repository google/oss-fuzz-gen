#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

extern int LLVMFuzzerTestOneInput_272(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsHPROFILE profile;

    // Initialize a cmsContext. For fuzzing, we can use a simple NULL context.
    context = cmsCreateContext(NULL, NULL);

    // Use the input data to create a profile, assuming the data is in a format
    // that can be interpreted by Little CMS. This is a simple example and may
    // need adjustment based on the actual expected input format.
    if (size > 0) {
        profile = cmsOpenProfileFromMemTHR(context, data, size);
    } else {
        profile = cmsCreateNULLProfileTHR(context);
    }

    // Clean up: close the profile and delete the context
    if (profile != NULL) {
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_272(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
