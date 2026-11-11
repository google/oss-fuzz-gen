#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    cmsHANDLE handle = NULL;

    // Initialize a cmsHANDLE with cmsIT8LoadFromMem if data size is sufficient
    if (size > 0) {
        handle = cmsIT8LoadFromMem(NULL, data, size); // Added NULL for ContextID
    }

    // Call the function-under-test
    if (handle != NULL) {
        const char *sheetType = cmsIT8GetSheetType(handle);
        // Use sheetType if necessary, here we just ensure it is called
    }

    // Cleanup
    if (handle != NULL) {
        cmsIT8Free(handle);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
