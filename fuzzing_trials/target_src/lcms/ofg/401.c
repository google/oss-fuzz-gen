#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_401(const uint8_t *data, size_t size) {
    // Initialize cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Ensure size is sufficient for a cmsUInt16Number
    if (size < sizeof(cmsUInt16Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize cmsUInt16Number pointer
    cmsUInt16Number alarmCode;
    cmsUInt16Number *alarmCodePtr = &alarmCode;

    // Call the function-under-test
    cmsGetAlarmCodesTHR(context, alarmCodePtr);

    // Clean up
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

    LLVMFuzzerTestOneInput_401(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
