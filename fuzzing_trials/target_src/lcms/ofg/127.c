#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to populate the structures
    if (size < sizeof(cmsCIEXYZ) * 2 + sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize the input cmsCIEXYZ structure
    const cmsCIEXYZ *inputXYZ = (const cmsCIEXYZ *)data;

    // Initialize the output cmsCIEXYZ structure
    cmsCIEXYZ outputXYZ;
    outputXYZ.X = 0.0;
    outputXYZ.Y = 0.0;
    outputXYZ.Z = 0.0;

    // Initialize the cmsCIELab structure
    const cmsCIELab *inputLab = (const cmsCIELab *)(data + sizeof(cmsCIEXYZ));

    // Call the function-under-test
    cmsLab2XYZ(inputXYZ, &outputXYZ, inputLab);

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

    LLVMFuzzerTestOneInput_127(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
