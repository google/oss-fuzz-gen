#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <cstdio>
#include <cstring>
#include <unistd.h> // For close() and remove()

// Include the necessary headers from json-c
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_util.h" // Include the header instead of the implementation file

extern "C" int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a temporary file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Exit if file creation fails
    }
    close(fd); // Close the file descriptor, we'll use the filename

    // Create a JSON object
    struct json_object *jobj = json_tokener_parse(
        fuzzed_data.ConsumeRemainingBytesAsString().c_str());

    if (jobj == nullptr) {
        remove(tmpl);
        return 0; // Exit if JSON parsing fails
    }

    // Call the function-under-test
    json_object_to_file(tmpl, jobj);

    // Cleanup

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from json_object_to_file to json_object_to_fd
    // Ensure dataflow is valid (i.e., non-null)
    if (!jobj) {
    	return 0;
    }
    double ret_json_object_get_double_yojta = json_object_get_double(jobj);
    if (ret_json_object_get_double_yojta < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!jobj) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from json_object_get_double to json_object_array_del_idx
    struct json_object* ret_json_object_new_array_ext_ljgix = json_object_new_array_ext(0);
    if (ret_json_object_new_array_ext_ljgix == NULL){
    	return 0;
    }
    int32_t ret_json_object_get_int_copnc = json_object_get_int(NULL);
    if (ret_json_object_get_int_copnc < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_json_object_new_array_ext_ljgix) {
    	return 0;
    }
    int ret_json_object_array_del_idx_nmcrr = json_object_array_del_idx(ret_json_object_new_array_ext_ljgix, (size_t )ret_json_object_get_double_yojta, (size_t )ret_json_object_get_int_copnc);
    if (ret_json_object_array_del_idx_nmcrr < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int32_t ret_json_object_get_int_vjwvy = json_object_get_int(jobj);
    if (ret_json_object_get_int_vjwvy < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!jobj) {
    	return 0;
    }
    int ret_json_object_to_fd_mwbgn = json_object_to_fd((int )ret_json_object_get_double_yojta, jobj, (int )ret_json_object_get_int_vjwvy);
    if (ret_json_object_to_fd_mwbgn < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    json_object_put(jobj);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
