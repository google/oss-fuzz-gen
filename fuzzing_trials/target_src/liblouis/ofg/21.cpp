#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h> // Include for write, close
#include <fcntl.h>  // Include for mkstemp
#include <sys/types.h> // Include for fsync
#include <sys/stat.h>  // Include for fsync

extern "C" {
    // Function-under-test declaration
    void lou_logFile(const char *);
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Avoid calling the function if the input size is too small
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to hold the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit early
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0; // If writing fails, exit early
    }

    // Ensure all data is written and file is closed properly
    fsync(fd);
    close(fd);

    // Check that the file is not empty before calling the function
    struct stat st;
    if (stat(tmpl, &st) != 0 || st.st_size == 0) {
        remove(tmpl);
        return 0; // Exit if the file is empty
    }

    // Call the function-under-test with the temporary file path
    lou_logFile(tmpl);

    // Remove the temporary file
    remove(tmpl);

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
