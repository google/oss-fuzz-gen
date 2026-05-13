#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Create a root JSON object
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return 0;
    }

    // Split the input data into two parts: key and value
    size_t key_size = data[0] % size; // Ensure key_size is within bounds
    size_t value_size = size - key_size - 1; // Ensure space for null terminator

    // Allocate memory for key and value strings
    char *key = (char *)malloc(key_size + 1);
    char *value = (char *)malloc(value_size + 1);

    if (key == NULL || value == NULL) {
        cJSON_Delete(root);
        free(key);
        free(value);
        return 0;
    }

    // Copy data into key and value strings
    memcpy(key, data + 1, key_size);
    key[key_size] = '\0'; // Null-terminate the key string
    memcpy(value, data + 1 + key_size, value_size);
    value[value_size] = '\0'; // Null-terminate the value string

    // Create a new JSON item
    cJSON *item = cJSON_CreateString(value);
    if (item == NULL) {
        cJSON_Delete(root);
        free(key);
        free(value);
        return 0;
    }

    // Add the item to the JSON object
    cJSON_bool result = cJSON_AddItemToObject(root, key, item);

    // Clean up
    cJSON_Delete(root);
    free(key);
    free(value);

    return result;
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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
