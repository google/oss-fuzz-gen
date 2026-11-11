#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts
    size_t json_size = size / 2;
    size_t key_size = size - json_size;

    // Create null-terminated strings for JSON and key
    char *json_data = (char *)malloc(json_size + 1);
    char *key_data = (char *)malloc(key_size + 1);

    if (!json_data || !key_data) {
        free(json_data);
        free(key_data);
        return 0;
    }

    memcpy(json_data, data, json_size);
    json_data[json_size] = '\0';

    memcpy(key_data, data + json_size, key_size);
    key_data[key_size] = '\0';

    // Parse the JSON data
    cJSON *json = cJSON_Parse(json_data);
    if (json == NULL) {
        free(json_data);
        free(key_data);
        return 0;
    }

    // Create a new item to replace with
    cJSON *new_item = cJSON_CreateString("new_value");
    if (new_item == NULL) {
        cJSON_Delete(json);
        free(json_data);
        free(key_data);
        return 0;
    }

    // Call the function-under-test
    cJSON_ReplaceItemInObjectCaseSensitive(json, key_data, new_item);

    // Clean up
    cJSON_Delete(json);
    free(json_data);
    free(key_data);

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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
