#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_467(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to create a dummy context.
    if (size < sizeof(cmsContext)) {
        return 0;
    }

    // Initialize a cmsContext using the data provided by the fuzzer.
    // We will use the data to create a dummy context for fuzzing.
    cmsContext context = (cmsContext)data;

    // Call the function-under-test with the initialized context.
    cmsHPROFILE profile = cmsCreate_sRGBProfileTHR(context);

    // Perform cleanup if necessary.
    if (profile != NULL) {
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

    LLVMFuzzerTestOneInput_467(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
