#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    // Create a root JSON object
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return 0;

    // Create a new JSON item to replace
    cJSON *new_item = cJSON_CreateString("replacement");
    if (new_item == NULL) {
        cJSON_Delete(root);
        return 0;
    }

    // Use part of the input data as a key
    size_t key_length = data[0] % (size - 1) + 1; // Ensure key_length is at least 1
    char *key = (char *)malloc(key_length + 1);
    if (key == NULL) {
        cJSON_Delete(root);
        cJSON_Delete(new_item);
        return 0;
    }
    memcpy(key, data + 1, key_length);
    key[key_length] = '\0';

    // Add an initial item to the object with the same key
    cJSON *initial_item = cJSON_CreateString("initial");
    if (initial_item == NULL) {
        free(key);
        cJSON_Delete(root);
        cJSON_Delete(new_item);
        return 0;
    }
    cJSON_AddItemToObject(root, key, initial_item);

    // Call the function-under-test
    cJSON_ReplaceItemInObject(root, key, new_item);

    // Cleanup
    free(key);
    cJSON_Delete(root);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
