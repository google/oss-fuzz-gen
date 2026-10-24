#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "/src/cjson/cJSON.h"

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated and has enough size for a key
    if (size < 2 || data[size - 1] != '\0') {
        return 0;
    }

    // Create a new cJSON object
    cJSON *json_object = cJSON_CreateObject();
    if (json_object == NULL) {
        return 0;
    }

    // Use the data as the key for the array
    const char *key = (const char *)data;

    // Call the function-under-test
    cJSON *array = cJSON_AddArrayToObject(json_object, key);

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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
