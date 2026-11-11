#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_332(const uint8_t *data, size_t size) {
    cmsMLU *mlu = cmsMLUalloc(NULL, 1); // Allocate a cmsMLU object with a single language entry

    if (mlu == NULL || size < 1) {
        return 0;
    }

    // Allocate a buffer to hold the input data plus a null terminator
    char *null_terminated_data = (char *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Copy the input data to the buffer and add a null terminator
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Add some dummy translations to the cmsMLU object
    cmsMLUsetASCII(mlu, "en", "US", null_terminated_data);
    cmsMLUsetASCII(mlu, "fr", "FR", null_terminated_data);

    // Call the function-under-test
    cmsUInt32Number count = cmsMLUtranslationsCount(mlu);

    // Clean up
    free(null_terminated_data);
    cmsMLUfree(mlu);

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

    LLVMFuzzerTestOneInput_332(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
