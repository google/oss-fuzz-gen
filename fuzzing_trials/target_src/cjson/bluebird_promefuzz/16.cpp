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
#include "../cJSON.h"
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Prepare a buffer with null-terminated string
    char *buffer = new char[Size + 1];
    memcpy(buffer, Data, Size);
    buffer[Size] = '\0';

    // Create a string cJSON item
    cJSON *stringItem1 = cJSON_CreateString(buffer);
    if (!stringItem1) {
        delete[] buffer;
        return 0;
    }

    // Create a JSON array
    cJSON *jsonArray = cJSON_CreateArray();
    if (!jsonArray) {
        cJSON_Delete(stringItem1);
        delete[] buffer;
        return 0;
    }

    // Create additional string items
    cJSON *stringItem2 = cJSON_CreateString(buffer);
    cJSON *stringItem3 = cJSON_CreateString(buffer);
    cJSON *stringItem4 = cJSON_CreateString(buffer);

    // Initialize hooks with default (NULL)
    cJSON_Hooks hooks = { nullptr, nullptr };
    cJSON_InitHooks(&hooks);

    // Delete the first string item
    cJSON_Delete(stringItem1);

    // Get the size of the array (should be 0 initially)
    int arraySize = cJSON_GetArraySize(jsonArray);

    // Add string items to the array
    if (stringItem2) {
        cJSON_AddItemToArray(jsonArray, stringItem2);
    }
    if (stringItem3) {
        cJSON_AddItemToArray(jsonArray, stringItem3);
    }

    // Create a new JSON object and add a string item to it
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject && stringItem4) {
        cJSON_AddItemToObject(jsonObject, "key", stringItem4);
    }

    // Cleanup
    cJSON_Delete(jsonArray);
    cJSON_Delete(jsonObject);
    delete[] buffer;

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
