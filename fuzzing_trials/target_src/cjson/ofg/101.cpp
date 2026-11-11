#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Create a root JSON object
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return 0;
    }

    // Split the input data into two parts
    size_t key_size = data[0] % size; // Ensure key_size is less than size
    size_t item_data_size = size - key_size - 1; // Ensure there's at least one byte for item

    // Create a key string from the first part of the data
    char *key = (char *)malloc(key_size + 1);
    if (key == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    memcpy(key, data + 1, key_size);
    key[key_size] = '\0'; // Null-terminate the key

    // Create a cJSON item from the second part of the data
    cJSON *item = cJSON_CreateString((const char *)(data + 1 + key_size));
    if (item == NULL) {
        free(key);
        cJSON_Delete(root);
        return 0;
    }

    // Add the item to the root object with the generated key
    cJSON_bool result = cJSON_AddItemToObject(root, key, item);

    // Clean up
    free(key);
    cJSON_Delete(root);

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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
