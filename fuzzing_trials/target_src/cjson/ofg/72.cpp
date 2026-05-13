#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../cJSON.h"

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size); /* required by C89 */

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts
    size_t mid = size / 2;
    const uint8_t *data1 = data;
    size_t size1 = mid;
    const uint8_t *data2 = data + mid;
    size_t size2 = size - mid;

    // Ensure both parts are null-terminated
    char *json_string1 = (char *)malloc(size1 + 1);
    if (json_string1 == NULL) {
        return 0;
    }
    memcpy(json_string1, data1, size1);
    json_string1[size1] = '\0';

    char *json_string2 = (char *)malloc(size2 + 1);
    if (json_string2 == NULL) {
        free(json_string1);
        return 0;
    }
    memcpy(json_string2, data2, size2);
    json_string2[size2] = '\0';

    // Parse the JSON strings
    cJSON *array = cJSON_Parse(json_string1);
    cJSON *new_item = cJSON_Parse(json_string2);

    if (array == NULL || new_item == NULL) {
        free(json_string1);
        free(json_string2);
        if (array != NULL) cJSON_Delete(array);
        if (new_item != NULL) cJSON_Delete(new_item);
        return 0;
    }

    // Fuzz the index for replacing an item in the array
    int index = (int)(data[0] % cJSON_GetArraySize(array));

    // Call the function under test
    cJSON_ReplaceItemInArray(array, index, new_item);

    // Clean up
    cJSON_Delete(array);
    free(json_string1);
    free(json_string2);

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

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
