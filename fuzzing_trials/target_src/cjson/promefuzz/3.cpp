// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_Parse at cJSON.c:1227:23 in cJSON.h
// cJSON_CreateString at cJSON.c:2531:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateStringReference at cJSON.c:2548:23 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_AddItemToObject at cJSON.c:2119:26 in cJSON.h
// cJSON_SetValuestring at cJSON.c:435:21 in cJSON.h
// cJSON_SetValuestring at cJSON.c:435:21 in cJSON.h
// cJSON_GetObjectItem at cJSON.c:1983:23 in cJSON.h
// cJSON_GetObjectItem at cJSON.c:1983:23 in cJSON.h
// cJSON_SetValuestring at cJSON.c:435:21 in cJSON.h
// cJSON_SetValuestring at cJSON.c:435:21 in cJSON.h
// cJSON_GetObjectItem at cJSON.c:1983:23 in cJSON.h
// cJSON_GetObjectItem at cJSON.c:1983:23 in cJSON.h
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

static char* createNullTerminatedString(const uint8_t* Data, size_t Size) {
    char* str = static_cast<char*>(malloc(Size + 1));
    if (str) {
        memcpy(str, Data, Size);
        str[Size] = '\0';
    }
    return str;
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a null-terminated string from input data
    char* jsonString = createNullTerminatedString(Data, Size);
    if (!jsonString) return 0;

    // Parse JSON
    cJSON* root = cJSON_Parse(jsonString);
    if (!root) {
        free(jsonString);
        return 0;
    }

    // Create a cJSON string
    cJSON* stringItem = cJSON_CreateString(jsonString);
    if (!stringItem) {
        cJSON_Delete(root);
        free(jsonString);
        return 0;
    }

    // Create a cJSON string reference
    cJSON* stringRefItem = cJSON_CreateStringReference(jsonString);

    // Add items to the root object
    cJSON_AddItemToObject(root, "stringItem", stringItem);
    cJSON_AddItemToObject(root, "stringRefItem", stringRefItem);

    // Set value strings
    cJSON_SetValuestring(stringItem, "newStringValue1");
    cJSON_SetValuestring(stringRefItem, "newStringValue2");

    // Retrieve object items
    cJSON* retrievedItem1 = cJSON_GetObjectItem(root, "stringItem");
    cJSON* retrievedItem2 = cJSON_GetObjectItem(root, "stringRefItem");

    // Further set value strings
    cJSON_SetValuestring(retrievedItem1, "anotherNewStringValue1");
    cJSON_SetValuestring(retrievedItem2, "anotherNewStringValue2");

    // Retrieve object items again
    cJSON_GetObjectItem(root, "stringItem");
    cJSON_GetObjectItem(root, "stringRefItem");

    // Clean up
    cJSON_Delete(root);
    free(jsonString);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
