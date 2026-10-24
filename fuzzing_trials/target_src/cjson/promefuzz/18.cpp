// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_AddRawToObject at cJSON.c:2222:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include "cJSON.h"
}

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    // Step 1: Create a cJSON object
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        // If creation fails, return early
        return 0;
    }

    // Step 2: Prepare data for cJSON_AddRawToObject
    // Use the first part of the data as the key
    const size_t keyLength = Size > 0 ? (Size / 2) : 0;
    const size_t rawLength = Size - keyLength;

    char *key = nullptr;
    char *raw = nullptr;

    if (keyLength > 0) {
        key = new char[keyLength + 1];
        std::memcpy(key, Data, keyLength);
        key[keyLength] = '\0';
    }

    if (rawLength > 0) {
        raw = new char[rawLength + 1];
        std::memcpy(raw, Data + keyLength, rawLength);
        raw[rawLength] = '\0';
    }

    // Step 3: Add raw JSON string to the object
    cJSON *item = cJSON_AddRawToObject(jsonObject, key, raw);

    // Step 4: Clean up allocated memory
    if (key != nullptr) {
        delete[] key;
    }
    if (raw != nullptr) {
        delete[] raw;
    }

    // Step 5: Delete the cJSON object
    cJSON_Delete(jsonObject);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
