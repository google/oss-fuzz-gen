#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <magic.h>

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    const char *magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Initialize magic_set and ensure it's not NULL
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        fprintf(stderr, "Failed to initialize magic_set\n");
        return 0;
    }

    // Load default magic database
    if (magic_load(ms, NULL) != 0) {
        fprintf(stderr, "Failed to load magic database: %s\n", magic_error(ms));
        magic_close(ms);
        return 0;
    }

    // Create a temporary file and write the fuzzing input data to it
    char tmp_filename[] = "/tmp/fuzz_inputXXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        fprintf(stderr, "Failed to create temporary file\n");
        magic_close(ms);
        return 0;
    }

    // Write the fuzzing input data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        fprintf(stderr, "Failed to write data to temporary file\n");
        close(fd);
        unlink(tmp_filename);
        magic_close(ms);
        return 0;
    }

    // Reset the file descriptor's offset to the beginning
    lseek(fd, 0, SEEK_SET);

    // Call the function-under-test
    const char *result = magic_descriptor(ms, fd);

    // Check the result (optional, for debugging purposes)
    if (result != NULL) {
        printf("Magic descriptor result: %s\n", result);
    } else {
        fprintf(stderr, "Magic descriptor returned NULL: %s\n", magic_error(ms));
    }

    // Clean up
    close(fd);
    unlink(tmp_filename);
    magic_close(ms);

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
