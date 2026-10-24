#include <sys/stat.h>
#include <string.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string>
#include "/src/json-c/json_object.h"
#include "/src/json-c/json_tokener.h"
#include "/src/json-c/json_util.h"  // Include the header instead of the .c file

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a temporary file to use its file descriptor
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    // Ensure file descriptor is valid
    if (fd == -1) {
        return 0;
    }

    // Create a json_object from the remaining fuzzed data
    std::string json_str = fuzzed_data.ConsumeRemainingBytesAsString();
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function json_tokener_parse with json_object_from_file
    struct json_object *jobj = json_object_from_file(json_str.c_str());
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // If parsing failed, clean up and return
    if (jobj == nullptr) {
        close(fd);
        return 0;
    }

    // Consume an integer for the flags argument
    int flags = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test
    json_object_to_fd(fd, jobj, flags);

    // Clean up
    json_object_put(jobj);
    close(fd);

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
