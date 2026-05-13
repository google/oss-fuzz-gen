#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include "/src/json-c/json_object.h"  // Include the correct header for json_object functions
#include "/src/json-c/json_util.h"    // Include the correct header for json_object_to_file function

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Create a FuzzedDataProvider to manage the input data
    FuzzedDataProvider fuzzed_data(data, size);

    // Generate a random length string for the JSON object key
    std::string json_key = fuzzed_data.ConsumeRandomLengthString(10);

    // Generate a random length string for the JSON object value
    std::string json_value = fuzzed_data.ConsumeRandomLengthString(50);

    // Create a new JSON object
    struct json_object *jobj = json_object_new_object();

    // Add the key-value pair to the JSON object
    json_object_object_add(jobj, json_key.c_str(), json_object_new_string(json_value.c_str()));

    // Create a temporary file to use as the filename
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        json_object_put(jobj);
        return 0;
    }
    close(fd);

    // Call the function-under-test
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of json_object_to_file
    json_object_to_file(NULL, jobj);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Clean up
    json_object_put(jobj);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
