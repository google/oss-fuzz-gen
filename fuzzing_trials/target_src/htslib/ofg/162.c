#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <htslib/hts.h>
#include <htslib/hfile.h>

int LLVMFuzzerTestOneInput_162(const uint8_t *data, size_t size) {
    hFILE *hfile = NULL;
    char mode[] = "r"; // Read mode
    char format[] = "text"; // Assuming a text format for simplicity

    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If unable to create a temp file, exit
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0; // If unable to write full data, exit
    }

    // Close the file descriptor
    close(fd);

    // Open the temporary file using hfile
    hfile = hopen(tmpl, mode);
    if (hfile == NULL) {
        unlink(tmpl);
        return 0; // If unable to open the file, exit
    }

    // Call the function-under-test
    htsFile *hts_file = hts_hopen(hfile, tmpl, format);
    if (hts_file != NULL) {
        hts_close(hts_file);
    }

    // Cleanup
    hclose(hfile);
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

    LLVMFuzzerTestOneInput_162(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
