#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h> // Include for mkstemp
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    struct bpf_object *obj = NULL;
    char *path = NULL;
    int fd = -1;

    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use as the path
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Duplicate the path to ensure it's null-terminated
    path = strdup(tmpl);
    if (path == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    bpf_object__unpin_programs(obj, path);

    // Clean up
    free(path);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
