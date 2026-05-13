#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "/src/htslib/htslib/hfile.h" // Correct path for hfile.h

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    hFILE *file = NULL;
    void *buffer = NULL;
    ssize_t result;

    // Ensure size is non-zero to allocate a buffer
    if (size == 0) {
        return 0;
    }

    // Initialize a buffer with the given data
    buffer = malloc(size);
    if (buffer == NULL) {
        return 0;
    }

    // Create a temporary file and write data into it
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        free(buffer);
        return 0;
    }

    // Write data to the file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        free(buffer);
        return 0;
    }

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Open the file with hFILE using hopen
    file = hopen(tmpl, "r");
    if (file == NULL) {
        close(fd);
        free(buffer);
        return 0;
    }

    // Call the function-under-test
    result = hpeek(file, buffer, size);

    // Clean up
    hclose(file);
    close(fd);
    free(buffer);
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

    LLVMFuzzerTestOneInput_46(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
