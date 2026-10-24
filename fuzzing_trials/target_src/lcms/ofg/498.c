#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_498(const uint8_t *data, size_t size) {
    // Initialize variables for the function-under-test
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number n = (cmsUInt32Number)size;

    // Call the function-under-test
    cmsSEQ *seq = cmsAllocProfileSequenceDescription(context, n);

    // Clean up resources
    if (seq != NULL) {
        cmsFreeProfileSequenceDescription(seq);
    }
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

    LLVMFuzzerTestOneInput_498(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
