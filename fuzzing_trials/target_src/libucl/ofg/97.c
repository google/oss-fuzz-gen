#include <stdint.h>
#include <stddef.h>
#include <ucl.h>
#include <unistd.h>
#include <fcntl.h>

// Function prototype for the function-under-test
struct ucl_emitter_functions * ucl_object_emit_fd_funcs(int fd);

int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Create a temporary file to obtain a file descriptor
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    // Ensure the file descriptor is valid
    if (fd == -1) {
        return 0;
    }

    // Call the function-under-test with the file descriptor
    struct ucl_emitter_functions *funcs = ucl_object_emit_fd_funcs(fd);

    // Clean up: close the file descriptor and remove the temporary file
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

    LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
