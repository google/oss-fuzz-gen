#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include "/src/json-c/json_object.h" // Include for json_object functions
#include "/src/json-c/json_tokener.h" // Include for json_tokener_parse
#include "/src/json-c/json_util.h" // Include for declarations of json_object_to_fd and other utility functions

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    // Initialize FuzzedDataProvider
    FuzzedDataProvider fuzzed_data(data, size);

    // Create a temporary file for the file descriptor
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If mkstemp fails, exit early
    }

    // Ensure the file descriptor is valid by opening it
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    // Consume some bytes to create a JSON object
    std::string json_str = fuzzed_data.ConsumeRandomLengthString();
    struct json_object *jobj = json_tokener_parse(json_str.c_str());
    if (jobj == nullptr) {
        close(fd);
        return 0; // If parsing fails, exit early
    }

    // Consume an integer for the flag
    int flag = fuzzed_data.ConsumeIntegral<int>();

    // Call the function-under-test
    json_object_to_fd(fd, jobj, flag);

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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
