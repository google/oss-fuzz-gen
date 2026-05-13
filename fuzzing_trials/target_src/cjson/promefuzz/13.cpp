// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_CreateArray at cJSON.c:2598:23 in cJSON.h
// cJSON_CreateNumber at cJSON.c:2505:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_AddItemToArray at cJSON.c:2061:26 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_CreateArrayReference at cJSON.c:2571:23 in cJSON.h
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
extern "C" {
#include "cJSON.h"
}

#include <cstdint>
#include <cstdlib>

static void fuzz_cjson(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) {
        return; // Not enough data to extract a double value
    }

    // Extract a double value from the input data
    double num;
    std::memcpy(&num, Data, sizeof(double));

    // Create a JSON array
    cJSON *jsonArray = cJSON_CreateArray();
    if (!jsonArray) {
        return; // Failed to create array
    }

    // Create a JSON number
    cJSON *jsonNumber = cJSON_CreateNumber(num);
    if (!jsonNumber) {
        cJSON_Delete(jsonArray);
        return; // Failed to create number
    }

    // Add the number to the array
    cJSON_bool success = cJSON_AddItemToArray(jsonArray, jsonNumber);
    if (!success) {
        cJSON_Delete(jsonNumber); // Clean up number if adding fails
        cJSON_Delete(jsonArray);
        return;
    }

    // Create a reference to the array
    cJSON *arrayRef = cJSON_CreateArrayReference(jsonArray);
    if (!arrayRef) {
        cJSON_Delete(jsonArray); // Clean up original array
        return; // Failed to create array reference
    }

    // Clean up the reference and the original array
    cJSON_Delete(arrayRef);
    cJSON_Delete(jsonArray);
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    fuzz_cjson(Data, Size);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
