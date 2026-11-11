#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "lcms2.h" // Assuming the function is part of the Little CMS library

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    // Ensure the buffer size matches the expected size for cmsGetAlarmCodesTHR
    const size_t expectedSize = 256; // Adjusted to a safer size based on typical CMS usage
    cmsUInt16Number alarmCodes[expectedSize]; // Initialize an array to hold alarm codes

    // Check if the size is sufficient for the operation
    if (size < sizeof(cmsUInt16Number) * expectedSize) {
        return 0; // Ensure there's enough data to fill the alarmCodes array
    }

    // Initialize a CMS context if required by the library (assuming it might be needed)
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0; // Handle context creation failure
    }

    // Call the function-under-test with the context
    cmsGetAlarmCodesTHR(context, alarmCodes);

    // Optionally, you can add code to examine or log the alarmCodes array
    // for (int i = 0; i < expectedSize; i++) {
    //     printf("Alarm Code %d: %u\n", i, alarmCodes[i]);
    // }

    // Clean up the CMS context
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

    LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
