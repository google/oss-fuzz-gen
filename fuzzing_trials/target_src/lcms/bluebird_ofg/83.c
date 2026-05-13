#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Initialize cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Check if size is sufficient to fill cmsViewingConditions structure
    if (size < sizeof(cmsViewingConditions)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Allocate memory for cmsViewingConditions and copy data into it
    cmsViewingConditions *viewingConditions = (cmsViewingConditions *)malloc(sizeof(cmsViewingConditions));
    if (viewingConditions == NULL) {
        cmsDeleteContext(context);
        return 0;
    }
    memcpy(viewingConditions, data, sizeof(cmsViewingConditions));

    // Call the function-under-test
    cmsHANDLE handle = cmsCIECAM02Init(context, viewingConditions);

    // Clean up
    if (handle != NULL) {
        cmsCIECAM02Done(handle);
    }
    free(viewingConditions);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
