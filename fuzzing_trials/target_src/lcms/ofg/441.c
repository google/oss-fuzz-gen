#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_441(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a null-terminated string
    if (size < 1) return 0;
    
    // Allocate memory for a null-terminated string
    char *sheetType = (char *)malloc(size + 1);
    if (sheetType == NULL) return 0;

    // Copy data into the string and null-terminate it
    memcpy(sheetType, data, size);
    sheetType[size] = '\0';

    // Create a dummy cmsHANDLE
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        free(sheetType);
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsIT8SetSheetType(handle, sheetType);

    // Clean up
    cmsIT8Free(handle);
    free(sheetType);

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

    LLVMFuzzerTestOneInput_441(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
