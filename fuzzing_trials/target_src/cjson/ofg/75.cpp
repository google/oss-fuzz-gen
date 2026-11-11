#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Create a root JSON object
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return 0;
    }

    // Use the first byte of data to determine the boolean value
    cJSON_bool bool_value = (data[0] % 2 == 0) ? cJSON_True : cJSON_False;

    // Use the remaining data as a key, ensuring it is null-terminated
    size_t key_length = size - 1;
    char *key = (char *)malloc(key_length + 1);
    if (key == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    memcpy(key, data + 1, key_length);
    key[key_length] = '\0';

    // Call the function-under-test
    cJSON *result = cJSON_AddBoolToObject(root, key, bool_value);

    // Clean up
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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
