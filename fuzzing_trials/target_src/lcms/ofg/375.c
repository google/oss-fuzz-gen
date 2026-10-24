#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_375(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char **properties = NULL;
    cmsUInt32Number result;

    // Initialize the LCMS context
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure that the data is not empty and can be used for further operations
    if (size > 0) {
        // Attempt to read the data into the IT8 handle
        cmsIT8LoadFromMem(handle, data, size);
    }

    // Call the function under test
    result = cmsIT8EnumProperties(handle, &properties);

    // Free allocated resources
    if (properties != NULL) {
        for (cmsUInt32Number i = 0; i < result; i++) {
            free(properties[i]);
        }
        free(properties);
    }
    cmsIT8Free(handle);

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

    LLVMFuzzerTestOneInput_375(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
