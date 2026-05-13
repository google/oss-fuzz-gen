#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/lcms/include/lcms2.h" // Correct path for the lcms2 library

int LLVMFuzzerTestOneInput_404(const uint8_t *data, size_t size) {
    cmsHANDLE handle;
    char *patchName;
    
    // Initialize the handle with a non-NULL value
    handle = cmsIT8Alloc(NULL);
    if (handle == NULL) {
        return 0; // Early exit if handle allocation fails
    }

    // Load the IT8 data from the input
    if (!cmsIT8LoadFromMem(handle, data, size)) {
        cmsIT8Free(handle);
        return 0; // Early exit if IT8 data loading fails
    }
    
    // Ensure the data is null-terminated for use as a string
    patchName = (char *)malloc(size + 1);
    if (patchName == NULL) {
        cmsIT8Free(handle);
        return 0; // Early exit if memory allocation fails
    }
    
    memcpy(patchName, data, size);
    patchName[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    // Assuming the patchName should be a valid name within the IT8 data
    cmsIT8GetPatchByName(handle, patchName);

    // Clean up
    free(patchName);
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

    LLVMFuzzerTestOneInput_404(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
