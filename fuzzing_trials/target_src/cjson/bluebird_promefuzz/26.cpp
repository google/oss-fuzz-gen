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
#include "../cJSON.h"

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Create a JSON string from the input data
    char *jsonString = (char *)malloc(Size + 1);
    if (!jsonString) {
        return 0;
    }
    memcpy(jsonString, Data, Size);
    jsonString[Size] = '\0';

    // Parse the JSON string
    cJSON *json = cJSON_Parse(jsonString);
    if (!json) {
        free(jsonString);
        return 0;
    }

    // Perform a series of operations on the parsed JSON
    cJSON *item1 = cJSON_GetObjectItemCaseSensitive(json, "key1");
    if (item1) {
        cJSON_IsString(item1);
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_GetObjectItemCaseSensitive to cJSON_Compare
    cJSON* ret_cJSON_CreateBool_mrjnf = cJSON_CreateBool(cJSON_Raw);
    if (ret_cJSON_CreateBool_mrjnf == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!json) {
    	return 0;
    }
    cJSON_bool ret_cJSON_IsArray_wsjxn = cJSON_IsArray(json);
    if (ret_cJSON_IsArray_wsjxn < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_cJSON_CreateBool_mrjnf) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!item1) {
    	return 0;
    }
    cJSON_bool ret_cJSON_Compare_wikfa = cJSON_Compare(ret_cJSON_CreateBool_mrjnf, item1, ret_cJSON_IsArray_wsjxn);
    if (ret_cJSON_Compare_wikfa < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    cJSON *item2 = cJSON_GetObjectItemCaseSensitive(json, "key2");
    if (item2) {
        cJSON_IsTrue(item2);
    }

    cJSON *item3 = cJSON_GetObjectItemCaseSensitive(json, "key3");
    cJSON *item4 = cJSON_GetObjectItemCaseSensitive(json, "key4");

    if (item3) {
        cJSON *duplicate = cJSON_Duplicate(item3, cJSON_True);
        if (duplicate) {
            cJSON *item5 = cJSON_GetObjectItemCaseSensitive(duplicate, "key5");
            cJSON *item6 = cJSON_GetObjectItemCaseSensitive(duplicate, "key6");
            if (item5 && item6) {
                cJSON_Compare(item5, item6, cJSON_True);
            }
            cJSON_Delete(duplicate);
        }
    }

    // Clean up
    cJSON_Delete(json);
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
