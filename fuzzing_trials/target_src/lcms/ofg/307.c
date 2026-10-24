#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_307(const uint8_t *data, size_t size) {
    // Initialize the CMS context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure the size is non-zero for valid input
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    cmsHANDLE handle = cmsIT8LoadFromMem(context, (const void *)data, (cmsUInt32Number)size);

    // Clean up the CMS handle if it was successfully created
    if (handle != NULL) {
        cmsIT8Free(handle);
    }

    // Clean up the CMS context
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

    LLVMFuzzerTestOneInput_307(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
