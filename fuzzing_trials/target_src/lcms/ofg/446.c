#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_446(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsFloat64Number)) {
        return 0; // Not enough data to proceed
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    cmsUInt32Number rows = 3; // Example fixed size
    cmsUInt32Number cols = 3; // Example fixed size

    cmsFloat64Number matrix[9];
    cmsFloat64Number offset[3];

    // Ensure we have enough data to fill the matrix and offset
    size_t required_size = sizeof(matrix) + sizeof(offset);
    if (size < required_size) {
        cmsDeleteContext(context);
        return 0;
    }

    // Copy data into matrix and offset
    memcpy(matrix, data, sizeof(matrix));
    memcpy(offset, data + sizeof(matrix), sizeof(offset));

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocMatrix(context, rows, cols, matrix, offset);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }
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

    LLVMFuzzerTestOneInput_446(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
