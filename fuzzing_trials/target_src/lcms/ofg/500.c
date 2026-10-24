#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_500(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsContext) + 6 * sizeof(cmsUInt32Number) + 4 * sizeof(cmsFloat64Number)) {
        return 0;  // Ensure there's enough data
    }

    // Initialize variables
    cmsContext context = *(cmsContext *)data;
    data += sizeof(cmsContext);

    cmsUInt32Number intent = *(cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);

    cmsFloat64Number bp = *(cmsFloat64Number *)data;
    data += sizeof(cmsFloat64Number);

    cmsFloat64Number wp = *(cmsFloat64Number *)data;
    data += sizeof(cmsFloat64Number);

    cmsFloat64Number ch = *(cmsFloat64Number *)data;
    data += sizeof(cmsFloat64Number);

    cmsFloat64Number sw = *(cmsFloat64Number *)data;
    data += sizeof(cmsFloat64Number);

    cmsUInt32Number flags = *(cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);

    cmsUInt32Number dwFlags = *(cmsUInt32Number *)data;
    data += sizeof(cmsUInt32Number);

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateBCHSWabstractProfileTHR(context, intent, bp, wp, ch, sw, flags, dwFlags);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_500(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
