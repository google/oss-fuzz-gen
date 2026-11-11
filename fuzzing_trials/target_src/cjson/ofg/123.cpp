#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0;
    }

    // Split the input data into three parts for the three cJSON parameters
    size_t part_size = size / 3;
    const char *json_str1 = (const char *)data;
    const char *json_str2 = (const char *)(data + part_size);
    const char *json_str3 = (const char *)(data + 2 * part_size);

    // Parse the JSON strings into cJSON objects
    cJSON *item1 = cJSON_ParseWithLength(json_str1, part_size);
    cJSON *item2 = cJSON_ParseWithLength(json_str2, part_size);
    cJSON *replacement = cJSON_ParseWithLength(json_str3, size - 2 * part_size);

    if (item1 == NULL || item2 == NULL || replacement == NULL) {
        cJSON_Delete(item1);
        cJSON_Delete(item2);
        cJSON_Delete(replacement);
        return 0;
    }

    // Call the function-under-test
    cJSON_ReplaceItemViaPointer(item1, item2, replacement);

    // Clean up
    cJSON_Delete(item1);
    cJSON_Delete(item2);
    cJSON_Delete(replacement);

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

    LLVMFuzzerTestOneInput_123(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
