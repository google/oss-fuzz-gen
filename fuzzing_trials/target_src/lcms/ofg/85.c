#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt16Number) * 3) {
        return 0; // Not enough data to proceed
    }

    cmsCIELab lab;
    cmsUInt16Number encoded[3];

    // Copy data into encoded array, ensuring we do not read out of bounds
    for (size_t i = 0; i < 3; ++i) {
        encoded[i] = ((cmsUInt16Number)data[i * 2] << 8) | (cmsUInt16Number)data[i * 2 + 1];
    }

    // Call the function under test
    cmsLabEncoded2FloatV2(&lab, encoded);

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

    LLVMFuzzerTestOneInput_85(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
