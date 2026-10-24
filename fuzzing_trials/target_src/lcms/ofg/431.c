#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_431(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for creating a null-terminated string
    if (size == 0) return 0;

    // Create a null-terminated string from the input data
    char *comment = (char *)malloc(size + 1);
    if (!comment) return 0;

    memcpy(comment, data, size);
    comment[size] = '\0';

    // Create a dummy cmsHANDLE for testing
    cmsHANDLE handle = cmsIT8Alloc(NULL);
    if (!handle) {
        free(comment);
        return 0;
    }

    // Call the function under test
    cmsBool result = cmsIT8SetComment(handle, comment);

    // Clean up
    cmsIT8Free(handle);
    free(comment);

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

    LLVMFuzzerTestOneInput_431(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
