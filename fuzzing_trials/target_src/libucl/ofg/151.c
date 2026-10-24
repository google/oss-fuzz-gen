#include <stdint.h>
#include <stddef.h>
#include <ucl.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(ucl_object_t)) {
        return 0;
    }

    // Create two ucl_object_t objects from the input data
    ucl_object_t obj1, obj2;
    const ucl_object_t *obj1_ptr = &obj1;
    const ucl_object_t *obj2_ptr = &obj2;

    // Allocate memory to hold copies of the input data for obj1 and obj2
    char *obj1_data = (char *)malloc(size + 1); // +1 for null-termination
    char *obj2_data = (char *)malloc(size + 1); // +1 for null-termination

    if (obj1_data == NULL || obj2_data == NULL) {
        free(obj1_data);
        free(obj2_data);
        return 0;
    }

    // Copy data into the allocated memory
    memcpy(obj1_data, data, size);
    memcpy(obj2_data, data + sizeof(ucl_object_t), size - sizeof(ucl_object_t));

    // Ensure null-termination of strings
    obj1_data[size] = '\0';
    obj2_data[size - sizeof(ucl_object_t)] = '\0';

    // Initialize the objects with the copied data
    obj1.type = UCL_STRING;
    obj1.value.sv = obj1_data;

    obj2.type = UCL_STRING;
    obj2.value.sv = obj2_data;

    // Call the function under test
    int result = ucl_object_compare_qsort(&obj1_ptr, &obj2_ptr);

    // Free the allocated memory
    free(obj1_data);
    free(obj2_data);

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

    LLVMFuzzerTestOneInput_151(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
