#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read for cmsUInt16Number array
    if (size < sizeof(cmsUInt16Number) * 3) {
        return 0;
    }

    // Initialize cmsCIEXYZ structure
    cmsCIEXYZ xyz;
    xyz.X = 0.0;
    xyz.Y = 0.0;
    xyz.Z = 0.0;

    // Cast data to cmsUInt16Number pointer
    const cmsUInt16Number *encodedData = (const cmsUInt16Number *)data;

    // Call the function-under-test
    cmsXYZEncoded2Float(&xyz, encodedData);

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

    LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
