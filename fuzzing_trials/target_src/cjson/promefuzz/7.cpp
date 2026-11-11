// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_AddStringToObject at cJSON.c:2210:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_AddArrayToObject at cJSON.c:2246:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_AddNumberToObject at cJSON.c:2198:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_AddNumberToObject at cJSON.c:2198:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_AddItemToArray at cJSON.c:2061:26 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Print at cJSON.c:1307:22 in cJSON.h
// cJSON_free at cJSON.c:3202:20 in cJSON.h
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

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create the first JSON object
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return 0;
    }

    // Add a string to the object
    const char *key1 = "key1";
    char *value1 = new char[Size + 1];
    memcpy(value1, Data, Size);
    value1[Size] = '\0';
    cJSON *stringItem = cJSON_AddStringToObject(root, key1, value1);
    delete[] value1;
    if (stringItem == nullptr) {
        cJSON_Delete(root);
        return 0;
    }

    // Add an array to the object
    const char *arrayKey = "array";
    cJSON *array = cJSON_AddArrayToObject(root, arrayKey);
    if (array == nullptr) {
        cJSON_Delete(root);
        return 0;
    }

    // Create another JSON object
    cJSON *numberObject = cJSON_CreateObject();
    if (numberObject == nullptr) {
        cJSON_Delete(root);
        return 0;
    }

    // Add numbers to the object
    const char *numberKey1 = "number1";
    const char *numberKey2 = "number2";
    double number1 = static_cast<double>(Data[0]);
    double number2 = static_cast<double>(Size);
    if (cJSON_AddNumberToObject(numberObject, numberKey1, number1) == nullptr) {
        cJSON_Delete(root);
        cJSON_Delete(numberObject);
        return 0;
    }
    if (cJSON_AddNumberToObject(numberObject, numberKey2, number2) == nullptr) {
        cJSON_Delete(root);
        cJSON_Delete(numberObject);
        return 0;
    }

    // Add the object to the array
    if (!cJSON_AddItemToArray(array, numberObject)) {
        cJSON_Delete(root);
        cJSON_Delete(numberObject);
        return 0;
    }

    // Print the JSON structure
    char *jsonString = cJSON_Print(root);
    if (jsonString != nullptr) {
        // Normally we would do something with jsonString
        cJSON_free(jsonString);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
