#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Ensure there's enough data for a key and a value
    if (size < 2) {
        return 0;
    }

    // Split the input data into a key and a value
    size_t key_length = data[0] % (size - 1) + 1; // Ensure key_length is at least 1
    size_t value_length = size - key_length;

    char *key = (char *)malloc(key_length + 1);
    cJSON *value_json = cJSON_ParseWithLength((const char *)(data + key_length), value_length);

    if (key == NULL || value_json == NULL) {
        free(key);
        cJSON_Delete(value_json);
        return 0;
    }

    memcpy(key, data + 1, key_length);
    key[key_length] = '\0'; // Null-terminate the key

    cJSON *object = cJSON_CreateObject();
    if (object == NULL) {
        free(key);
        cJSON_Delete(value_json);
        return 0;
    }

    // Call the function-under-test
    cJSON_bool result = cJSON_AddItemToObjectCS(object, key, value_json);

    // Clean up
    free(key);
    cJSON_Delete(object);

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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
