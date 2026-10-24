#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <htslib/hts.h>
#include <htslib/hfile.h>

int LLVMFuzzerTestOneInput_161(const uint8_t *data, size_t size) {
    hFILE *hfile = NULL;
    char *mode = NULL;
    char *format = NULL;
    htsFile *htsfile = NULL;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;

    if (size < 2) {
        return 0;
    }

    // Create a temporary file
    fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the file using hFILE
    hfile = hopen(tmpl, "r");
    if (hfile == NULL) {
        return 0;
    }

    // Allocate and initialize mode and format strings
    mode = (char *)malloc(2);
    format = (char *)malloc(2);
    if (mode == NULL || format == NULL) {
        hclose(hfile);
        return 0;
    }

    // Set mode and format based on fuzz data
    mode[0] = (char)data[0];
    mode[1] = '\0';
    format[0] = (char)data[1];
    format[1] = '\0';

    // Call the function-under-test
    htsfile = hts_hopen(hfile, mode, format);

    // Clean up
    if (htsfile != NULL) {
        hts_close(htsfile);
    } else {
        hclose(hfile);
    }
    free(mode);
    free(format);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_161(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
