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

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double) * 2) {
        return 0;
    }

    // Extract two double values from the input data
    double num1;
    double num2;
    memcpy(&num1, Data, sizeof(double));
    memcpy(&num2, Data + sizeof(double), sizeof(double));

    // Create two cJSON numbers
    cJSON *number1 = cJSON_CreateNumber(num1);
    cJSON *number2 = cJSON_CreateNumber(num2);

    if (!number1 || !number2) {
        cJSON_Delete(number1);
        cJSON_Delete(number2);
        return 0;
    }

    // Create a cJSON object
    cJSON *jsonObject = cJSON_CreateObject();
    if (!jsonObject) {
        cJSON_Delete(number1);
        cJSON_Delete(number2);
        return 0;
    }

    // Add the first number to the object with a key
    const char *key1 = "number1";
    if (!cJSON_AddItemToObject(jsonObject, key1, number1)) {
        cJSON_Delete(number1); // cJSON_AddItemToObject does not delete on failure
        cJSON_Delete(number2);
        cJSON_Delete(jsonObject);
        return 0;
    }

    // Replace the item in the object with the second number
    const char *key2 = "number1"; // Using the same key to replace
    if (!cJSON_ReplaceItemInObject(jsonObject, key2, number2)) {
        cJSON_Delete(number2); // cJSON_ReplaceItemInObject does not delete on failure
        cJSON_Delete(jsonObject);
        return 0;
    }

    // Cleanup
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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
