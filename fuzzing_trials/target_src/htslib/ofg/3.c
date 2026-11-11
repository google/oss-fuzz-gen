#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>    // For close() and unlink()
#include <fcntl.h>     // For open() flags
#include "/src/htslib/htslib/hfile.h"  // Correct path for hfile.h

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Create a temporary file name
    char temp_filename[] = "/tmp/fuzz_tempfile_XXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(temp_filename);
        return 0;
    }
    close(fd);

    // Open the temporary file with htslib's hFILE interface using hopen
    hFILE *hfile = hopen(temp_filename, "r", 0);
    if (hfile == NULL) {
        unlink(temp_filename);
        return 0;
    }

    // Allocate a buffer to read data into
    char buffer[1024];
    ssize_t bytes_read;

    // Read data from the hFILE to ensure the input is processed
    while ((bytes_read = hread(hfile, buffer, sizeof(buffer))) > 0) {
        // Process the read data (for example, by just iterating over it)
        for (ssize_t i = 0; i < bytes_read; i++) {
            // Dummy processing: just access the data
            volatile char c = buffer[i];
            (void)c;  // Prevent unused variable warning
        }
    }

    // Close the hFILE and remove the temporary file
    hclose(hfile);
    unlink(temp_filename);

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

    LLVMFuzzerTestOneInput_3(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
