#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize the FuzzedDataProvider with the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Consume a random length string from the fuzzed data
    std::string json_str = fuzzed_data.ConsumeRandomLengthString();

    // Parse the JSON string to a json_object
    struct json_object *jobj = json_tokener_parse(json_str.c_str());

    // Ensure the json_object is not NULL before calling the function
    if (jobj != nullptr) {
        // Call the function-under-test
        json_bool result = json_object_get_boolean(jobj);

        // Clean up the json_object

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from json_object_get_boolean to json_object_set_boolean

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from json_object_get_boolean to json_object_set_boolean
        // Ensure dataflow is valid (i.e., non-null)
        if (!jobj) {
        	return 0;
        }
        struct json_object* ret_json_object_get_fioxo = json_object_get(jobj);
        if (ret_json_object_get_fioxo == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!jobj) {
        	return 0;
        }
        int ret_json_object_set_boolean_qpdib = json_object_set_boolean(jobj, result);
        if (ret_json_object_set_boolean_qpdib < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        struct json_object* ret_json_object_new_uint64_gddch = json_object_new_uint64(0);
        if (ret_json_object_new_uint64_gddch == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_json_object_new_uint64_gddch) {
        	return 0;
        }
        int ret_json_object_set_boolean_mvmdp = json_object_set_boolean(ret_json_object_new_uint64_gddch, result);
        if (ret_json_object_set_boolean_mvmdp < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        json_object_put(jobj);
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
