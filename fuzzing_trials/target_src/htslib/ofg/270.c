#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "/src/htslib/htslib/hfile.h"  // Correct path for the header file

int LLVMFuzzerTestOneInput_270(const uint8_t *data, size_t size) {
    // Create a temporary file to obtain a valid file descriptor
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;  // If unable to create a temporary file, exit early
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) == -1) {
        close(fd);
        unlink(tmpl);
        return 0;  // If unable to write data, exit early
    }

    // Reset the file offset to the beginning
    lseek(fd, 0, SEEK_SET);

    // Convert the fuzz data to a null-terminated string for the mode argument
    char mode[4];  // Assuming mode strings are short, e.g., "r", "w", "rw"
    size_t mode_len = size < 3 ? size : 3;  // Limit mode length to 3
    memcpy(mode, data, mode_len);
    mode[mode_len] = '\0';

    // Call the function-under-test
    hFILE *file = hdopen(fd, mode);

    // Clean up: close the file and remove the temporary file
    if (file != NULL) {
        hclose(file);
    }
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_270(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
