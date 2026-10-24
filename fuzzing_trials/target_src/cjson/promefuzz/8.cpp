// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_CreateIntArray at cJSON.c:2621:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_GetArrayItem at cJSON.c:1941:23 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateString at cJSON.c:2531:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateString at cJSON.c:2531:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
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
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "cJSON.h"

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 3) {
        return 0;
    }

    const int *intArray = reinterpret_cast<const int*>(Data);
    int arraySize = Size / sizeof(int);

    // Create a JSON object
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return 0;
    }

    // Create an integer array
    cJSON *intArrayJson = cJSON_CreateIntArray(intArray, arraySize);
    if (intArrayJson == nullptr) {
        cJSON_Delete(root);
        return 0;
    }

    // Get an item from the array
    cJSON *arrayItem = cJSON_GetArrayItem(intArrayJson, 0);

    // Add the integer array to the root object
    if (!cJSON_AddItemToObject(root, "intArray", intArrayJson)) {
        cJSON_Delete(intArrayJson);
        cJSON_Delete(root);
        return 0;
    }

    // Create another JSON object
    cJSON *object1 = cJSON_CreateObject();
    if (object1 == nullptr) {
        cJSON_Delete(root);
        return 0;
    }

    // Create a string from the input data
    char *stringData1 = new char[Size + 1];
    memcpy(stringData1, Data, Size);
    stringData1[Size] = '\0';

    cJSON *stringJson1 = cJSON_CreateString(stringData1);
    delete[] stringData1;

    if (stringJson1 == nullptr) {
        cJSON_Delete(object1);
        cJSON_Delete(root);
        return 0;
    }

    // Add the string to the first object
    if (!cJSON_AddItemToObject(object1, "string1", stringJson1)) {
        cJSON_Delete(stringJson1);
        cJSON_Delete(object1);
        cJSON_Delete(root);
        return 0;
    }

    // Create another JSON object
    cJSON *object2 = cJSON_CreateObject();
    if (object2 == nullptr) {
        cJSON_Delete(root);
        return 0;
    }

    // Create another string from the input data
    char *stringData2 = new char[Size + 1];
    memcpy(stringData2, Data, Size);
    stringData2[Size] = '\0';

    cJSON *stringJson2 = cJSON_CreateString(stringData2);
    delete[] stringData2;

    if (stringJson2 == nullptr) {
        cJSON_Delete(object2);
        cJSON_Delete(root);
        return 0;
    }

    // Add the string to the second object
    if (!cJSON_AddItemToObject(object2, "string2", stringJson2)) {
        cJSON_Delete(stringJson2);
        cJSON_Delete(object2);
        cJSON_Delete(root);
        return 0;
    }

    // Cleanup
    cJSON_Delete(object2);
    cJSON_Delete(object1);
    cJSON_Delete(root);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
