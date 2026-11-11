// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_CreateString at cJSON.c:2531:23 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_CreateArray at cJSON.c:2598:23 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_AddItemToArray at cJSON.c:2061:26 in cJSON.h
// cJSON_CreateNumber at cJSON.c:2505:23 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_CreateNumber at cJSON.c:2505:23 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
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

#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    // Ensure that Data is null-terminated for cJSON_CreateString
    char *inputString = new char[Size + 1];
    memcpy(inputString, Data, Size);
    inputString[Size] = '\0';

    // Create a JSON object
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        delete[] inputString;
        return 0;
    }

    // Create a JSON string
    cJSON *stringItem = cJSON_CreateString(inputString);
    if (stringItem) {
        cJSON_AddItemToObject(root, "string", stringItem);
    }

    // Create a JSON array
    cJSON *array = cJSON_CreateArray();
    if (array) {
        cJSON_AddItemToObject(root, "array", array);

        // Create a JSON object and add it to the array
        cJSON *arrayObject = cJSON_CreateObject();
        if (arrayObject) {
            cJSON_AddItemToArray(array, arrayObject);

            // Create a JSON number and add it to the array object
            cJSON *numberItem1 = cJSON_CreateNumber(42.0);
            if (numberItem1) {
                cJSON_AddItemToObject(arrayObject, "number1", numberItem1);
            }

            // Create another JSON number and add it to the array object
            cJSON *numberItem2 = cJSON_CreateNumber(3.14);
            if (numberItem2) {
                cJSON_AddItemToObject(arrayObject, "number2", numberItem2);
            }
        }
    }

    // Print the JSON structure to a string
    char *jsonString = cJSON_Print(root);
    if (jsonString) {
        // Normally you might do something with the jsonString here
        cJSON_free(jsonString);
    }

    // Clean up
    cJSON_Delete(root);
    delete[] inputString;

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
