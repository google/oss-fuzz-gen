// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_CreateFalse at cJSON.c:2483:23 in cJSON.h
// cJSON_CreateString at cJSON.c:2531:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateStringReference at cJSON.c:2548:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateObjectReference at cJSON.c:2560:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
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

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    // Ensure we have at least one byte for the string functions
    if (Size == 0) {
        return 0;
    }

    // Step 1: Invoke cJSON_CreateFalse
    cJSON *json_false = cJSON_CreateFalse();
    if (json_false == NULL) {
        return 0;
    }

    // Step 2: Prepare a null-terminated string for cJSON_CreateString
    char *string_data = new char[Size + 1];
    memcpy(string_data, Data, Size);
    string_data[Size] = '\0';

    // Step 3: Invoke cJSON_CreateString
    cJSON *json_string = cJSON_CreateString(string_data);
    delete[] string_data;
    if (json_string == NULL) {
        cJSON_Delete(json_false);
        return 0;
    }

    // Step 4: Invoke cJSON_CreateObject
    cJSON *json_object = cJSON_CreateObject();
    if (json_object == NULL) {
        cJSON_Delete(json_false);
        cJSON_Delete(json_string);
        return 0;
    }

    // Step 5: Invoke cJSON_CreateStringReference
    cJSON *json_string_ref = cJSON_CreateStringReference(json_string->valuestring);
    if (json_string_ref == NULL) {
        cJSON_Delete(json_false);
        cJSON_Delete(json_string);
        cJSON_Delete(json_object);
        return 0;
    }

    // Step 6: Clean up the first cJSON_Delete
    cJSON_Delete(json_false);

    // Step 7: Invoke cJSON_CreateObjectReference
    cJSON *json_object_ref = cJSON_CreateObjectReference(json_object);
    if (json_object_ref == NULL) {
        cJSON_Delete(json_string);
        cJSON_Delete(json_object);
        cJSON_Delete(json_string_ref);
        return 0;
    }

    // Step 8: Clean up the second cJSON_Delete
    cJSON_Delete(json_object);

    // Step 9: Clean up the third cJSON_Delete
    cJSON_Delete(json_string);

    // Step 10: Clean up the fourth cJSON_Delete
    cJSON_Delete(json_string_ref);

    // Step 11: Clean up the fifth cJSON_Delete
    cJSON_Delete(json_object_ref);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
