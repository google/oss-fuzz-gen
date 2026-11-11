#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsCIELCh)) {
        return 0; // Not enough data to populate cmsCIELCh
    }

    cmsCIELCh lch;
    cmsCIELab lab;

    // Copy data into cmsCIELCh structure
    memcpy(&lch, data, sizeof(cmsCIELCh));

    // Call the function under test
    cmsLCh2Lab(&lab, &lch);

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

    LLVMFuzzerTestOneInput_159(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
