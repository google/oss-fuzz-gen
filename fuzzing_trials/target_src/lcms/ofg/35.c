#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 3) return 0;

    // Create a handle for IT8 data
    cmsHANDLE it8 = cmsIT8Alloc(NULL);
    if (it8 == NULL) return 0;

    // Split the input data into three parts for the parameters
    size_t part_size = size / 3;
    char *param1 = (char *)malloc(part_size + 1);
    char *param2 = (char *)malloc(part_size + 1);
    char *param3 = (char *)malloc(size - 2 * part_size + 1);

    if (param1 == NULL || param2 == NULL || param3 == NULL) {
        cmsIT8Free(it8);
        free(param1);
        free(param2);
        free(param3);
        return 0;
    }

    // Copy the data into the parameters and null-terminate
    memcpy(param1, data, part_size);
    param1[part_size] = '\0';

    memcpy(param2, data + part_size, part_size);
    param2[part_size] = '\0';

    memcpy(param3, data + 2 * part_size, size - 2 * part_size);
    param3[size - 2 * part_size] = '\0';

    // Call the function-under-test
    cmsBool result = cmsIT8SetData(it8, param1, param2, param3);

    // Clean up
    cmsIT8Free(it8);
    free(param1);
    free(param2);
    free(param3);

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

    LLVMFuzzerTestOneInput_35(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
