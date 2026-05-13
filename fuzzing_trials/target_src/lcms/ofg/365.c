#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_365(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    const char *propertyName;
    const char **propertyValues;
    cmsUInt32Number result;

    // Initialize the handle with a valid value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the data is large enough to extract a null-terminated string
    if (size < 2) {
        cmsIT8Free(handle);
        return 0;
    }

    // Allocate memory for propertyName and copy data into it
    propertyName = (const char *)malloc(size + 1);
    if (propertyName == NULL) {
        cmsIT8Free(handle);
        return 0;
    }
    memcpy((char *)propertyName, data, size);
    ((char *)propertyName)[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    result = cmsIT8EnumPropertyMulti(handle, propertyName, &propertyValues);

    // Free allocated resources
    free((char *)propertyName);
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

    LLVMFuzzerTestOneInput_365(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
