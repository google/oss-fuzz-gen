// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_CreateString at cJSON.c:2531:23 in cJSON.h
// cJSON_CreateNumber at cJSON.c:2505:23 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
// cJSON_GetNumberValue at cJSON.c:109:22 in cJSON.h
// cJSON_GetNumberValue at cJSON.c:109:22 in cJSON.h
// cJSON_GetNumberValue at cJSON.c:109:22 in cJSON.h
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

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Step 1: Create a null-terminated string from the input data.
    char *inputString = new char[Size + 1];
    memcpy(inputString, Data, Size);
    inputString[Size] = '\0';

    // Step 2: Invoke cJSON_CreateString
    cJSON *stringItem = cJSON_CreateString(inputString);
    if (stringItem == nullptr) {
        delete[] inputString;
        return 0;
    }

    // Step 3: Create a number from the input data
    double numberValue = static_cast<double>(Data[0]); // Use the first byte as a simple number
    cJSON *numberItem = cJSON_CreateNumber(numberValue);
    if (numberItem == nullptr) {
        cJSON_Delete(stringItem);
        delete[] inputString;
        return 0;
    }

    // Step 4: Invoke cJSON_GetNumberValue multiple times
    double numVal1 = cJSON_GetNumberValue(numberItem);
    double numVal2 = cJSON_GetNumberValue(numberItem);
    double numVal3 = cJSON_GetNumberValue(numberItem);

    // Step 5: Cleanup
    cJSON_Delete(stringItem);
    cJSON_Delete(numberItem);
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
