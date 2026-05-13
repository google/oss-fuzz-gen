#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_374(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char **properties = NULL;
    cmsUInt32Number result;
    cmsContext context = cmsCreateContext(NULL, NULL);

    if (context == NULL) {
        return 0; // Failed to create context
    }

    // Check if size is sufficient for meaningful data
    if (size < 1) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize a cmsHANDLE using cmsIT8LoadFromMem
    handle = cmsIT8LoadFromMem(context, data, size);

    if (handle == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    result = cmsIT8EnumProperties(handle, &properties);

    // Clean up
    if (properties != NULL) {
        // Assuming properties is a NULL-terminated array of strings
        for (char **ptr = properties; *ptr != NULL; ++ptr) {
            free(*ptr);
        }
        free(properties);
    }

    cmsIT8Free(handle);
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

    LLVMFuzzerTestOneInput_374(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
