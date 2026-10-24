#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to create a valid JSON object and key
    }

    // Split the input data into two parts: JSON string and key
    size_t json_size = size / 2;
    size_t key_size = size - json_size;

    // Ensure the JSON string and key are null-terminated
    char *json_string = (char *)malloc(json_size + 1);
    char *key_string = (char *)malloc(key_size + 1);

    if (json_string == NULL || key_string == NULL) {
        free(json_string);
        free(key_string);
        return 0;
    }

    memcpy(json_string, data, json_size);
    json_string[json_size] = '\0';

    memcpy(key_string, data + json_size, key_size);
    key_string[key_size] = '\0';

    // Parse the JSON string
    cJSON *json = cJSON_Parse(json_string);
    if (json != NULL) {
        // Call the function-under-test
        cJSON_DeleteItemFromObjectCaseSensitive(json, key_string);
        // Clean up
        cJSON_Delete(json);
    }

    free(json_string);
    free(key_string);

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

    LLVMFuzzerTestOneInput_121(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
