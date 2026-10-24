#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "/src/lcms/include/lcms2_plugin.h" // Assuming this is the correct header for cmsIT8FindDataFormat

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    cmsHANDLE handle = cmsIT8Alloc(NULL); // Allocate a handle for the IT8 structure

    if (handle == NULL || size == 0) {
        return 0; // Exit if handle allocation fails or if size is 0
    }

    // Allocate and copy data to a null-terminated string
    char *dataStr = (char *)malloc(size + 1);
    if (dataStr == NULL) {
        cmsIT8Free(handle);
        return 0; // Exit if memory allocation fails
    }
    
    memcpy(dataStr, data, size);
    dataStr[size] = '\0'; // Null-terminate the string

    // Call the function under test
    cmsIT8FindDataFormat(handle, dataStr);

    // Clean up
    free(dataStr);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_108(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
