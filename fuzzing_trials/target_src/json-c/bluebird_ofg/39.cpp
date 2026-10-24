#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a portion of the input data for the first JSON object
    std::string first_json_str = fuzzed_data.ConsumeRandomLengthString();

    // Validate that the consumed string has a non-zero length
    if (first_json_str.empty()) {
        return 0;
    }

    // Consume the remaining data for the second JSON object
    std::string second_json_str = fuzzed_data.ConsumeRemainingBytesAsString();

    // Validate that the consumed string has a non-zero length
    if (second_json_str.empty()) {
        return 0;
    }

    // Parse the strings into JSON objects
    struct json_object *json_obj1 = json_tokener_parse(first_json_str.c_str());
    struct json_object *json_obj2 = json_tokener_parse(second_json_str.c_str());

    // Ensure that both JSON objects are not NULL
    if (json_obj1 != NULL && json_obj2 != NULL) {
        // Call the function-under-test
        int result = json_object_equal(json_obj1, json_obj2);
    }

    // Free the JSON objects
    if (json_obj1 != NULL) {
        json_object_put(json_obj1);
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from json_object_put to json_object_deep_copy
        struct json_object* ret_json_object_new_array_ext_hpipv = json_object_new_array_ext(-1);
        if (ret_json_object_new_array_ext_hpipv == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_json_object_new_array_ext_hpipv) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!json_obj1) {
        	return 0;
        }
        int ret_json_object_deep_copy_bzpiv = json_object_deep_copy(ret_json_object_new_array_ext_hpipv, &json_obj1, NULL);
        if (ret_json_object_deep_copy_bzpiv < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
}
    if (json_obj2 != NULL) {
        json_object_put(json_obj2);
    }

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
