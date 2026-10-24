// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_AddBoolToObject at cJSON.c:2186:22 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_AddBoolToObject at cJSON.c:2186:22 in cJSON.h
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
extern "C" {
#include "cJSON.h"
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    // Step 1: Create a cJSON object
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject == NULL) {
        return 0; // If creation fails, exit early
    }

    // Step 2: Add boolean values to the cJSON object
    // Use the input data to determine the boolean value and the name
    if (Size > 0) {
        // Use the first byte of the data as a boolean value
        cJSON_bool boolValue1 = Data[0] % 2 == 0 ? 1 : 0;
        const char *name1 = "bool1";

        cJSON *item1 = cJSON_AddBoolToObject(jsonObject, name1, boolValue1);
        if (item1 == NULL) {
            cJSON_Delete(jsonObject);
            return 0; // If adding fails, cleanup and exit
        }
    }

    if (Size > 1) {
        // Use the second byte of the data as a boolean value
        cJSON_bool boolValue2 = Data[1] % 2 == 0 ? 1 : 0;
        const char *name2 = "bool2";

        cJSON *item2 = cJSON_AddBoolToObject(jsonObject, name2, boolValue2);
        if (item2 == NULL) {
            cJSON_Delete(jsonObject);
            return 0; // If adding fails, cleanup and exit
        }
    }

    // Step 3: Cleanup
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
