#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Ensure there is enough data to process

    // Split the data into two parts for creating two cJSON objects
    size_t half_size = size / 2;

    // Create a cJSON object from the first half of the data
    char *first_half = (char *)malloc(half_size + 1);
    if (!first_half) return 0;
    memcpy(first_half, data, half_size);
    first_half[half_size] = '\0'; // Ensure null-termination

    cJSON *array = cJSON_Parse(first_half);
    free(first_half);

    if (!array) return 0; // If parsing failed, exit

    // Create a cJSON object from the second half of the data
    char *second_half = (char *)malloc(size - half_size + 1);
    if (!second_half) {
        cJSON_Delete(array);
        return 0;
    }
    memcpy(second_half, data + half_size, size - half_size);
    second_half[size - half_size] = '\0'; // Ensure null-termination

    cJSON *item = cJSON_Parse(second_half);
    free(second_half);

    if (!item) {
        cJSON_Delete(array);
        return 0; // If parsing failed, exit
    }

    // Call the function-under-test
    cJSON_bool result = cJSON_AddItemReferenceToArray(array, item);

    // Clean up
    cJSON_Delete(array);
    cJSON_Delete(item);

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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
