#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Split the input data for two JSON objects
    size_t mid = size / 2;

    // Create a null-terminated string for the first JSON object
    char *json_data1 = (char *)malloc(mid + 1);
    if (json_data1 == NULL) {
        return 0;
    }
    memcpy(json_data1, data, mid);
    json_data1[mid] = '\0';

    // Create a null-terminated string for the second JSON object
    char *json_data2 = (char *)malloc(size - mid + 1);
    if (json_data2 == NULL) {
        free(json_data1);
        return 0;
    }
    memcpy(json_data2, data + mid, size - mid);
    json_data2[size - mid] = '\0';

    // Parse the JSON objects
    cJSON *array = cJSON_Parse(json_data1);
    cJSON *new_item = cJSON_Parse(json_data2);

    // Check if parsing was successful
    if (array != NULL && new_item != NULL) {
        // Attempt to replace an item in the array
        int index = 0; // Use a fixed index for simplicity
        cJSON_ReplaceItemInArray(array, index, new_item);
    }

    // Clean up
    cJSON_Delete(array);
    cJSON_Delete(new_item);
    free(json_data1);
    free(json_data2);

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

    LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
