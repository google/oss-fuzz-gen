#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h> // for mkstemp
#include <string>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_util.h" // Include the header for json_object_to_file_ext

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a temporary file to pass as the filename
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit early
    }

    // Consume a portion of the input for the json_object
    std::string json_data = fuzzed_data.ConsumeRandomLengthString(fuzzed_data.remaining_bytes() / 2);
    if (json_data.empty()) {
        close(fd);
        unlink(tmpl);
        return 0; // If JSON data is empty, exit early
    }

    struct json_object *jobj = json_tokener_parse(json_data.c_str());
    if (jobj == nullptr) {
        close(fd);
        unlink(tmpl);
        return 0; // If JSON parsing fails, exit early
    }

    // Consume an integer for the flags parameter
    int flags = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test
    json_object_to_file_ext(tmpl, jobj, flags);

    // Clean up
    json_object_put(jobj);
    close(fd);
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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
