#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    // Create a cJSON object from the input data
    cJSON *json = cJSON_ParseWithLength((const char *)data, size);
    if (json == NULL) return 0;

    // Ensure the cJSON object is an array
    if (!cJSON_IsArray(json)) {
        cJSON_Delete(json);
        return 0;
    }

    // Use the first byte of data as the index for detaching an item
    int index = data[0] % cJSON_GetArraySize(json);

    // Call the function under test
    cJSON *detached_item = cJSON_DetachItemFromArray(json, index);

    // Clean up
    if (detached_item != NULL) {
        cJSON_Delete(detached_item);
    }
    cJSON_Delete(json);

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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
