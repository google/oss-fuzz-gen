#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_215(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context;
    cmsHPROFILE profile;

    // Ensure the data size is sufficient for creating a context
    if (size < sizeof(cmsContext)) {
        return 0;
    }

    // Create a context using cmsCreateContext
    context = cmsCreateContext(NULL, NULL);

    // Call the function-under-test
    profile = cmsCreate_OkLabProfile(context);

    // Clean up the profile if it was created successfully
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    // Clean up the context if it was created successfully
    if (context != NULL) {
        cmsDeleteContext(context);
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

    LLVMFuzzerTestOneInput_215(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
