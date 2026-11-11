#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated and has at least one character for the key
    if (size < 1 || data[size - 1] != '\0') {
        return 0;
    }

    // Create a cJSON object
    cJSON *json_object = cJSON_CreateObject();
    if (json_object == NULL) {
        return 0;
    }

    // Use the input data as the key for the cJSON_AddNullToObject function
    const char *key = (const char *)data;

    // Call the function-under-test
    cJSON *result = cJSON_AddNullToObject(json_object, key);

    // Clean up
    cJSON_Delete(json_object);

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

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
