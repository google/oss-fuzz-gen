#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include "/src/json-c/json_object.h" // Added for json_object functions
#include "/src/json-c/json_util.h"   // Include the header file instead of the .c file

extern "C" int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Create a temporary file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the file
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        return 0;
    }

    // Ensure the file descriptor is reset to the beginning
    lseek(fd, 0, SEEK_SET);

    // Call the function-under-test
    struct json_object *obj = json_object_from_fd(fd);

    // Clean up
    json_object_put(obj);
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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
