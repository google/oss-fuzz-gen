#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Create a cJSON object to use as the target object
    cJSON *object = cJSON_CreateObject();
    if (object == NULL) {
        return 0;
    }

    // Create a cJSON item to replace in the object
    cJSON *new_item = cJSON_CreateString("new_value");
    if (new_item == NULL) {
        cJSON_Delete(object);
        return 0;
    }

    // Use the first byte of data as a key for the object
    char key[2] = { (char)data[0], '\0' };

    // Add an initial item to the object with the same key
    cJSON *initial_item = cJSON_CreateString("initial_value");
    if (initial_item == NULL) {
        cJSON_Delete(object);
        cJSON_Delete(new_item);
        return 0;
    }
    cJSON_AddItemToObject(object, key, initial_item);

    // Call the function-under-test
    cJSON_ReplaceItemInObject(object, key, new_item);

    // Clean up
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
