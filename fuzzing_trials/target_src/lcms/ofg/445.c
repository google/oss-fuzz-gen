#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_445(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number rows = 3; // Example size, can be varied
    cmsUInt32Number cols = 3; // Example size, can be varied

    if (size < rows * cols * sizeof(cmsFloat64Number)) {
        cmsDeleteContext(context);
        return 0;
    }

    const cmsFloat64Number *matrix = (const cmsFloat64Number *)data;
    const cmsFloat64Number *offsets = NULL;

    if (size >= rows * cols * sizeof(cmsFloat64Number) + rows * sizeof(cmsFloat64Number)) {
        offsets = (const cmsFloat64Number *)(data + rows * cols * sizeof(cmsFloat64Number));
    }

    cmsStage *stage = cmsStageAllocMatrix(context, rows, cols, matrix, offsets);

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

    LLVMFuzzerTestOneInput_445(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
