#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_280(const uint8_t *data, size_t size) {
    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Ensure there is enough data to initialize cmsViewingConditions
    if (size < sizeof(cmsViewingConditions)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize cmsViewingConditions with data
    cmsViewingConditions viewingConditions;
    memcpy(&viewingConditions, data, sizeof(cmsViewingConditions));

    // Call the function-under-test
    cmsHANDLE handle = cmsCIECAM02Init(context, &viewingConditions);

    // Clean up
    cmsCIECAM02Done(handle);
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

    LLVMFuzzerTestOneInput_280(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
