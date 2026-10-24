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
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create the first JSON object
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return 0;
    }

    // Add a string to the object
    const char *key1 = "key1";
    char *value1 = new char[Size + 1];
    memcpy(value1, Data, Size);
    value1[Size] = '\0';
    cJSON *stringItem = cJSON_AddStringToObject(root, key1, value1);
    delete[] value1;
    if (stringItem == nullptr) {
        cJSON_Delete(root);
        return 0;
    }

    // Add an array to the object
    const char *arrayKey = "array";
    cJSON *array = cJSON_AddArrayToObject(root, arrayKey);
    if (array == nullptr) {
        cJSON_Delete(root);
        return 0;
    }

    // Create another JSON object
    cJSON *numberObject = cJSON_CreateObject();
    if (numberObject == nullptr) {
        cJSON_Delete(root);
        return 0;
    }

    // Add numbers to the object

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from cJSON_CreateObject to cJSON_AddItemReferenceToArray using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!array) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!root) {
    	return 0;
    }
    cJSON_bool ret_cJSON_AddItemReferenceToArray_mycjz = cJSON_AddItemReferenceToArray(array, root);
    if (ret_cJSON_AddItemReferenceToArray_mycjz < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_AddItemReferenceToArray to cJSON_InsertItemInArray
    // Ensure dataflow is valid (i.e., non-null)
    if (!root) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_AddItemReferenceToArray to cJSON_CreateFloatArray
    // Ensure dataflow is valid (i.e., non-null)
    if (!root) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cJSON_AddItemReferenceToArray to cJSON_CreateDoubleArray
    // Ensure dataflow is valid (i.e., non-null)
    if (!root) {
    	return 0;
    }
    double ret_cJSON_GetNumberValue_oprph = cJSON_GetNumberValue(root);
    if (ret_cJSON_GetNumberValue_oprph < 0){
    	return 0;
    }
    cJSON* ret_cJSON_CreateDoubleArray_ydlck = cJSON_CreateDoubleArray(&ret_cJSON_GetNumberValue_oprph, ret_cJSON_AddItemReferenceToArray_mycjz);
    if (ret_cJSON_CreateDoubleArray_ydlck == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    cJSON_bool ret_cJSON_IsFalse_krvjh = cJSON_IsFalse(root);
    if (ret_cJSON_IsFalse_krvjh < 0){
    	return 0;
    }
    cJSON* ret_cJSON_CreateFloatArray_vyxuo = cJSON_CreateFloatArray((const float *)&ret_cJSON_IsFalse_krvjh, ret_cJSON_AddItemReferenceToArray_mycjz);
    if (ret_cJSON_CreateFloatArray_vyxuo == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    cJSON* ret_cJSON_CreateArrayReference_umvzv = cJSON_CreateArrayReference(root);
    if (ret_cJSON_CreateArrayReference_umvzv == NULL){
    	return 0;
    }
    cJSON* ret_cJSON_CreateNumber_tcwkc = cJSON_CreateNumber(cJSON_Invalid);
    if (ret_cJSON_CreateNumber_tcwkc == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_cJSON_CreateArrayReference_umvzv) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_cJSON_CreateNumber_tcwkc) {
    	return 0;
    }
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function cJSON_InsertItemInArray with cJSON_ReplaceItemInArray
    cJSON_bool ret_cJSON_InsertItemInArray_akjjb = cJSON_ReplaceItemInArray(ret_cJSON_CreateArrayReference_umvzv, ret_cJSON_AddItemReferenceToArray_mycjz, ret_cJSON_CreateNumber_tcwkc);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    if (ret_cJSON_InsertItemInArray_akjjb < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    const char *numberKey1 = "number1";
    const char *numberKey2 = "number2";
    double number1 = static_cast<double>(Data[0]);
    double number2 = static_cast<double>(Size);
    if (cJSON_AddNumberToObject(numberObject, numberKey1, number1) == nullptr) {
        cJSON_Delete(root);
        cJSON_Delete(numberObject);
        return 0;
    }
    if (cJSON_AddNumberToObject(numberObject, numberKey2, number2) == nullptr) {
        cJSON_Delete(root);
        cJSON_Delete(numberObject);
        return 0;
    }

    // Add the object to the array
    if (!cJSON_AddItemToArray(array, numberObject)) {
        cJSON_Delete(root);
        cJSON_Delete(numberObject);
        return 0;
    }

    // Print the JSON structure
    char *jsonString = cJSON_Print(root);
    if (jsonString != nullptr) {
        // Normally we would do something with jsonString
        cJSON_free(jsonString);
    }

    // Clean up
    cJSON_Delete(root);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
