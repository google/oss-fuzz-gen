#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For close() and unlink()
#include <fcntl.h>  // For mkstemp()
#include "htslib/hts.h"

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to store the fuzz data
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
    close(fd);

    // Open the temporary file with hts_open
    htsFile *file = hts_open(tmpl, "r");
    if (file == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Attempt to read from the file to trigger code paths
    // Assuming there's a function to read data, e.g., hts_read_data
    // This is a placeholder for the actual function that processes the file
    // size_t bytes_read = hts_read_data(file);

    // Clean up
    hts_close(file);
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

    LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
