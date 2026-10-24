#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Create a null-terminated string for the key
    size_t key_length = data[0] % (size - 1) + 1; // Ensure at least 1 character
    char *key = (char *)malloc(key_length + 1);
    if (key == NULL) {
        return 0;
    }
    memcpy(key, data + 1, key_length);
    key[key_length] = '\0';

    // Parse the remaining data as a JSON object
    cJSON *json = cJSON_ParseWithLength((const char *)data + key_length + 1, size - key_length - 1);
    if (json == NULL) {
        free(key);
        return 0;
    }

    // Call the function-under-test
    cJSON_DeleteItemFromObject(json, key);

    // Clean up
    cJSON_Delete(json);
    free(key);

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
