#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_425(const uint8_t *data, size_t size) {
    // Create a profile from the input data
    cmsHPROFILE profile = cmsOpenProfileFromMem(data, size);

    // Check if profile creation was successful
    if (profile != NULL) {
        // Do something with the profile if needed
        // For example, we can use the profile in a function that requires it
        // or simply release it after creation to test the creation and deletion process.
        
        // Release the profile to avoid memory leaks
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

    LLVMFuzzerTestOneInput_425(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
