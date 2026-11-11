#include <fuzzer/FuzzedDataProvider.h>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_util.h" // Include the correct header for json_object_to_file_ext
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unistd.h> // For close and unlink

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a temporary file to pass the filename
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If the file cannot be created, exit early
    }
    
    // Consume a portion of the data to create a json_object
    std::string json_data = fuzzed_data.ConsumeRandomLengthString(fuzzed_data.remaining_bytes() / 2);
    if (json_data.empty()) {
        close(fd);
        return 0; // If no data is consumed, exit early
    }
    
    struct json_object *jobj = json_tokener_parse(json_data.c_str());
    if (jobj == nullptr) {
        close(fd);
        return 0; // If JSON parsing fails, exit early
    }

    // Consume an integer for the third parameter
    int flags = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test
    json_object_to_file_ext(tmpl, jobj, flags);

    // Clean up
    json_object_put(jobj);
    close(fd);
    unlink(tmpl); // Remove the temporary file

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
