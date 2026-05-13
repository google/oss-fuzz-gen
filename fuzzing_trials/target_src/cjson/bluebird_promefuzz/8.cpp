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

#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
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
            
                // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_AddItemToObject to cJSON_Compare
                cJSON* ret_cJSON_CreateBool_ltfsg = cJSON_CreateBool(cJSON_Number);
                if (ret_cJSON_CreateBool_ltfsg == NULL){
                	return 0;
                }
                // Ensure dataflow is valid (i.e., non-null)
                if (!array) {
                	return 0;
                }
                cJSON_bool ret_cJSON_IsBool_dhmzm = cJSON_IsBool(array);
                if (ret_cJSON_IsBool_dhmzm < 0){
                	return 0;
                }
                // Ensure dataflow is valid (i.e., non-null)
                if (!ret_cJSON_CreateBool_ltfsg) {
                	return 0;
                }
                // Ensure dataflow is valid (i.e., non-null)
                if (!root) {
                	return 0;
                }

                // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_IsBool to cJSON_CreateStringArray
                void* ret_cJSON_malloc_bacdu = cJSON_malloc(1);
                if (ret_cJSON_malloc_bacdu == NULL){
                	return 0;
                }
                // Ensure dataflow is valid (i.e., non-null)
                if (!ret_cJSON_malloc_bacdu) {
                	return 0;
                }
                cJSON* ret_cJSON_CreateStringArray_zoyva = cJSON_CreateStringArray((const char **)&ret_cJSON_malloc_bacdu, ret_cJSON_IsBool_dhmzm);
                if (ret_cJSON_CreateStringArray_zoyva == NULL){
                	return 0;
                }
                // End mutation: Producer.APPEND_MUTATOR
                
                cJSON_bool ret_cJSON_Compare_akuiz = cJSON_Compare(ret_cJSON_CreateBool_ltfsg, root, ret_cJSON_IsBool_dhmzm);
                if (ret_cJSON_Compare_akuiz < 0){
                	return 0;
                }
                // End mutation: Producer.APPEND_MUTATOR
                
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
