#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Ensure that the input data is null-terminated and has a minimum size
    if (size < 1 || data[size - 1] != '\0') {
        return 0;
    }

    // Create a cJSON object to add the true value to
    cJSON *json_object = cJSON_CreateObject();
    if (json_object == NULL) {
        return 0;
    }

    // Use the input data as the key for the true value
    const char *key = (const char *)data;

    // Call the function-under-test
    cJSON *result = cJSON_AddTrueToObject(json_object, key);

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

    LLVMFuzzerTestOneInput_110(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
