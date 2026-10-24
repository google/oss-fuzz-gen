#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h> // Assuming the function is part of the LCMS2 library

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for at least one cmsUInt16Number
    if (size < sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Calculate how many cmsUInt16Number elements can be created from the input data
    size_t num_elements = size / sizeof(cmsUInt16Number);

    // Allocate memory for the cmsUInt16Number array
    cmsUInt16Number *alarmCodes = (cmsUInt16Number *)malloc(num_elements * sizeof(cmsUInt16Number));
    if (alarmCodes == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy data into the cmsUInt16Number array
    for (size_t i = 0; i < num_elements; ++i) {
        alarmCodes[i] = ((cmsUInt16Number *)data)[i];
    }

    // Call the function-under-test
    cmsSetAlarmCodes(alarmCodes);

    // Free the allocated memory
    free(alarmCodes);

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

    LLVMFuzzerTestOneInput_146(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
