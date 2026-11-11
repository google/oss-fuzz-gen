#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

extern "C" {
    #include "magic.h"
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    struct magic_set *ms;
    int pipefd[2];

    // Initialize a magic_set object
    ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Ensure size is large enough to write to a pipe
    if (size == 0) {
        magic_close(ms);
        return 0;
    }

    // Create a pipe
    if (pipe(pipefd) == -1) {
        magic_close(ms);
        return 0;
    }

    // Write data to the pipe
    if (write(pipefd[1], data, size) == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        magic_close(ms);
        return 0;
    }

    // Close the write end of the pipe
    close(pipefd[1]);

    // Call the function-under-test with the read end of the pipe
    const char *result = magic_descriptor(ms, pipefd[0]);

    // Ensure the result is not null
    if (result != NULL) {
        // Print the result for debugging purposes
        printf("Magic Descriptor: %s\n", result);
    } else {
        // If result is null, print an error message for debugging
        printf("Magic Descriptor: (null)\n");
    }

    // Clean up
    close(pipefd[0]);
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
