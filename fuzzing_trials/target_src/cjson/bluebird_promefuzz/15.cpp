#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstddef>
#include "../cJSON.h"

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    // Create a cJSON object
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        return 0; // If creation fails, exit early
    }

    // Prepare a key name from the input data
    // Ensure the key name is null-terminated and has a reasonable length
    size_t keyLength = Size < 256 ? Size : 255;
    char key[256];
    if (Size > 0) {
        memcpy(key, Data, keyLength);
        key[keyLength] = '\0';
    } else {
        key[0] = '\0';
    }

    // Add a true value to the object with the given key
    cJSON *addedItem = cJSON_AddTrueToObject(jsonObject, key);

    // Check if the item was added successfully
    if (addedItem == nullptr) {
        cJSON_Delete(jsonObject);
        return 0; // Exit if adding failed
    }

    // Clean up the cJSON object
    cJSON_Delete(jsonObject);

    return 0;
}
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
