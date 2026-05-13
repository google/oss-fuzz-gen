#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Ensure the data size is sufficient for the void* and const char* parameters
    if (size < sizeof(void*) + 1) {
        cmsDeleteContext(context);
        return 0;
    }

    // Allocate memory for the void* parameter
    void* memPtr = malloc(size);
    if (memPtr == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Copy the data into the allocated memory
    memcpy(memPtr, data, size);

    // Create a null-terminated string for the fourth parameter
    char mode[4] = "r";
    if (size > 0) {
        mode[0] = (char)data[0];
        mode[1] = '\0'; // Ensure null-termination
    }

    // Call the function-under-test
    cmsIOHANDLER* handler = cmsOpenIOhandlerFromMem(context, memPtr, (cmsUInt32Number)size, mode);

    // Clean up
    if (handler != NULL) {
        cmsCloseIOhandler(handler);
    }
    free(memPtr);
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

    LLVMFuzzerTestOneInput_71(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
