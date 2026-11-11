#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    cmsContext context;
    void *userData = (void *)data;

    // Initialize a dummy context using cmsCreateContext
    context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Extract a cmsUInt32Number from the input data to use it meaningfully
    cmsUInt32Number intent = *(cmsUInt32Number *)data;

    // Call the function-under-test with a valid intent
    cmsContext duplicatedContext = cmsDupContext(context, userData);
    if (duplicatedContext != NULL) {
        // Create an array of cmsUInt16Number to pass to cmsSetAlarmCodes
        cmsUInt16Number alarmCodes[cmsMAXCHANNELS] = {0}; // Initialize with zeros or any valid values

        // Use the duplicated context with a valid function call
        cmsSetAlarmCodes(alarmCodes);
    }

    // Clean up
    cmsDeleteContext(context);
    if (duplicatedContext != NULL) {
        cmsDeleteContext(duplicatedContext);
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
