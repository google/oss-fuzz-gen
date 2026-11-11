#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "/src/htslib/htslib/hts.h"  // Correct path for htsFile structure and hts_close function

int LLVMFuzzerTestOneInput_239(const uint8_t *data, size_t size) {
    // Create a temporary file to be used with htsFile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Exit if file creation fails
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0; // Exit if writing fails
    }

    // Rewind the file descriptor to the beginning
    lseek(fd, 0, SEEK_SET);

    // Open the file using htsFile structure
    htsFile *htsfile = hts_open(tmpl, "r");
    if (htsfile == NULL) {
        close(fd);
        return 0; // Exit if htsFile creation fails
    }

    // Call the function-under-test
    hts_close(htsfile);

    // Clean up
    close(fd);
    unlink(tmpl); // Remove the temporary file

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

    LLVMFuzzerTestOneInput_239(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
