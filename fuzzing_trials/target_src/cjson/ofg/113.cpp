#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/cjson/cJSON.h"

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }

    // Calculate the number of integers we can extract from the data
    int num_elements = size / sizeof(int);

    // Allocate memory for the integer array
    int *int_array = (int *)malloc(num_elements * sizeof(int));
    if (int_array == NULL) {
        return 0;
    }

    // Copy data into the integer array
    for (int i = 0; i < num_elements; ++i) {
        int_array[i] = ((int *)data)[i];
    }

    // Call the function-under-test
    cJSON *json_array = cJSON_CreateIntArray(int_array, num_elements);

    // Clean up
    if (json_array != NULL) {
        cJSON_Delete(json_array);
    }
    free(int_array);

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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
