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
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "../cJSON.h"

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    cJSON *root = cJSON_CreateObject();
    cJSON *array = cJSON_CreateArray();
    cJSON *item1 = cJSON_CreateString("item1");
    cJSON *item2 = cJSON_CreateString("item2");
    cJSON *item3 = cJSON_CreateString("item3");
    cJSON *item4 = cJSON_CreateString("item4");
    cJSON *item5 = cJSON_CreateString("item5");

    // Add items to objects
    cJSON_AddItemToObject(root, "key1", item1);
    cJSON_AddItemToObject(root, "key2", item2);
    cJSON_AddItemToObjectCS(root, "key3", cJSON_CreateString("item3_CS"));
    cJSON_AddItemToObjectCS(root, "key4", cJSON_CreateString("item4_CS"));
    cJSON_AddItemToObjectCS(root, "key5", cJSON_CreateString("item5_CS"));

    // Add item references to array
    cJSON_AddItemReferenceToArray(array, item1);
    cJSON_AddItemReferenceToArray(array, item2);

    // Add item references to object
    cJSON_AddItemReferenceToObject(root, "ref1", item3);
    cJSON_AddItemReferenceToObject(root, "ref2", item4);
    cJSON_AddItemReferenceToObject(root, "ref3", item5);

    // Delete items from array and object
    cJSON_DeleteItemFromArray(array, 0);
    cJSON_DeleteItemFromObject(root, "key1");
    cJSON_DeleteItemFromObject(root, "key2");
    cJSON_DeleteItemFromObjectCaseSensitive(root, "key3");
    cJSON_DeleteItemFromObjectCaseSensitive(root, "key4");

    // Minify JSON string
    char *jsonStr = cJSON_Print(root);
    if (jsonStr) {
        cJSON_Minify(jsonStr);
        cJSON_free(jsonStr);
    }

    // Clean up
    cJSON_Delete(root);
    cJSON_Delete(array);
    cJSON_Delete(item3);
    cJSON_Delete(item4);
    cJSON_Delete(item5);

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
