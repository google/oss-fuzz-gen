#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Ensure there's enough data for a null-terminated string
    if (size < 2) return 0;

    // Split the data into two parts: one for the key and one for the JSON strings
    size_t key_length = data[0] % (size - 1) + 1; // Ensure key_length is at least 1 and less than size
    size_t json_length = size - key_length;

    // Allocate memory for the key and ensure it's null-terminated
    char *key = (char *)malloc(key_length + 1);
    if (!key) return 0;
    memcpy(key, data + 1, key_length);
    key[key_length] = '\0';

    // Allocate memory for the JSON string and ensure it's null-terminated
    char *json_string = (char *)malloc(json_length + 1);
    if (!json_string) {
        free(key);
        return 0;
    }
    memcpy(json_string, data + 1 + key_length, json_length);
    json_string[json_length] = '\0';

    // Parse the JSON string to create a cJSON object
    cJSON *json_object = cJSON_Parse(json_string);
    if (!json_object) {
        free(key);
        free(json_string);
        return 0;
    }

    // Create a new cJSON item to reference
    cJSON *item_to_reference = cJSON_CreateString("reference");

    // Call the function under test
    cJSON_bool result = cJSON_AddItemReferenceToObject(json_object, key, item_to_reference);

    // Clean up
    cJSON_Delete(json_object);
    cJSON_Delete(item_to_reference);
    free(key);
    free(json_string);

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

    LLVMFuzzerTestOneInput_145(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
