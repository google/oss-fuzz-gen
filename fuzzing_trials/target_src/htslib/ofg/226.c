#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Function-under-test
int hfile_has_plugin(const char *filename);

int LLVMFuzzerTestOneInput_226(const uint8_t *data, size_t size) {
    // Check if the input size is reasonable
    if (size == 0) {
        return 0; // Nothing to process
    }

    // Create a temporary file name template
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit the fuzzer
    }

    // Ensure the file is writable
    if (ftruncate(fd, 0) == -1) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0; // If writing fails, clean up and exit
    }

    // Close the file descriptor to flush the data
    close(fd);

    // Call the function-under-test with the temporary file name
    // Consider checking the return value or behavior of the function
    int result = hfile_has_plugin(tmpl);

    // Log the result for debugging purposes (optional)
    printf("hfile_has_plugin returned: %d\n", result);

    // Clean up: remove the temporary file
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_226(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
