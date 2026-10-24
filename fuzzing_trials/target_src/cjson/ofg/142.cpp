#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Ensure the data is null-terminated for string operations
    char *json_data = (char *)malloc(size + 1);
    if (json_data == NULL) {
        return 0;
    }
    memcpy(json_data, data, size);
    json_data[size] = '\0';

    // Parse the JSON data
    cJSON *json = cJSON_Parse(json_data);
    free(json_data);

    if (json == NULL) {
        return 0;
    }

    // Extract a key from the data to use for cJSON_HasObjectItem
    size_t key_length = size / 2;
    char *key = (char *)malloc(key_length + 1);
    if (key == NULL) {
        cJSON_Delete(json);
        return 0;
    }
    memcpy(key, data + size / 2, key_length);
    key[key_length] = '\0';

    // Call the function-under-test
    cJSON_bool result = cJSON_HasObjectItem(json, key);

    // Clean up
    free(key);
    cJSON_Delete(json);

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

    LLVMFuzzerTestOneInput_142(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
