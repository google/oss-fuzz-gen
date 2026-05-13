#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>  // Include this header for mkstemp, close, and unlink
#include <fcntl.h>   // Include this header for write
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate a htsFile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the temporary file as an htsFile
    htsFile *file = hts_open(tmpl, "r");
    if (file != NULL) {
        // Call the function-under-test
        hts_close(file);
    }

    // Clean up the temporary file
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

    LLVMFuzzerTestOneInput_27(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
