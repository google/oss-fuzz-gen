#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_483(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a memory profile from the input data
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0;
    }

    // Initialize a struct tm to store the date-time
    struct tm creationDateTime;
    
    // Call the function under test
    cmsBool result = cmsGetHeaderCreationDateTime(hProfile, &creationDateTime);

    // Clean up
    cmsCloseProfile(hProfile);

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

    LLVMFuzzerTestOneInput_483(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
