#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    if (size < sizeof(double)) {
        return 0;
    }

    // Calculate the number of doubles we can extract from the data
    int num_doubles = size / sizeof(double);
    double *double_array = (double *)malloc(num_doubles * sizeof(double));

    if (double_array == NULL) {
        return 0;
    }

    // Copy the data into the double array
    for (int i = 0; i < num_doubles; ++i) {
        double_array[i] = ((double *)data)[i];
    }

    // Call the function-under-test
    cJSON *json_array = cJSON_CreateDoubleArray(double_array, num_doubles);

    // Clean up
    if (json_array != NULL) {
        cJSON_Delete(json_array);
    }
    free(double_array);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
