#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "/src/htslib/htslib/hfile.h" // Correct path for hFILE and hdopen

int LLVMFuzzerTestOneInput_271(const uint8_t *data, size_t size) {
    int fd;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    hFILE *file = NULL;
    char buffer[1024]; // Buffer for reading data
    ssize_t bytes_read;

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Call the function-under-test
    file = hdopen(fd, "r");
    if (file != NULL) {
        // Perform operations on the file if necessary
        // Read some data from the file to ensure coverage
        while ((bytes_read = hread(file, buffer, sizeof(buffer))) > 0) {
            // Process the read data if necessary
            // For fuzzing, just ensure that the read is performed
        }

        // Close the hFILE
        hclose(file);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_271(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
