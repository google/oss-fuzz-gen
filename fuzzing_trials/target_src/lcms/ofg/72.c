#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract the necessary parameters
    if (size < sizeof(cmsUInt32Number) + 1) {
        return 0;
    }

    // Initialize the cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Allocate memory for the handler buffer
    void *handlerBuffer = malloc(size);
    if (handlerBuffer == NULL) {
        cmsDeleteContext(context);
        return 0;
    }
    memcpy(handlerBuffer, data, size);

    // Extract cmsUInt32Number from the input data
    cmsUInt32Number bufferSize;
    memcpy(&bufferSize, data, sizeof(cmsUInt32Number));

    // Ensure bufferSize is not larger than the actual data size
    bufferSize = bufferSize % size;

    // Prepare a string for the last parameter
    const char *accessMode = "r"; // Using a simple read mode for testing

    // Call the function under test
    cmsIOHANDLER *handler = cmsOpenIOhandlerFromMem(context, handlerBuffer, bufferSize, accessMode);

    // Clean up
    if (handler != NULL) {
        cmsCloseIOhandler(handler);
    }
    free(handlerBuffer);
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

    LLVMFuzzerTestOneInput_72(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
