#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <magic.h>

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    struct magic_set *magic = NULL;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    // Check if size is zero to avoid writing an empty file
    if (size == 0) {
        return 0;
    }

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Initialize the magic library
    magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_file(magic, tmpl);

    // Check if result is not NULL
    if (result == NULL) {
        fprintf(stderr, "magic_file failed: %s\n", magic_error(magic));
    } else {
        // Print the result to ensure the function is being utilized
        printf("Magic file result: %s\n", result);
    }

    // Clean up
    magic_close(magic);
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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
