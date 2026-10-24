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
extern "C" {
#include "../cJSON.h"
}

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    // Create three JSON arrays
    cJSON *array1 = cJSON_CreateArray();
    cJSON *array2 = cJSON_CreateArray();
    cJSON *array3 = cJSON_CreateArray();

    if (!array1 || !array2 || !array3) {
        // Clean up and return if any array creation failed
        if (array1) cJSON_Delete(array1);
        if (array2) cJSON_Delete(array2);
        if (array3) cJSON_Delete(array3);
        return 0;
    }

    // Add items to the first array
    cJSON_AddItemToArray(array1, cJSON_CreateArray());
    cJSON_AddItemToArray(array1, cJSON_CreateArray());
    cJSON_AddItemToArray(array1, cJSON_CreateArray());

    // Attempt to duplicate the first array
    cJSON *duplicateArray = cJSON_Duplicate(array1, cJSON_True);

    // Detach an item from the first array
    cJSON *detachedItem = cJSON_DetachItemFromArray(array1, 0);

    // Clean up
    cJSON_Delete(array1);
    cJSON_Delete(array2);
    cJSON_Delete(array3);
    if (duplicateArray) cJSON_Delete(duplicateArray);
    if (detachedItem) cJSON_Delete(detachedItem);

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
