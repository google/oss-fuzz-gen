#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>      // Include for close() and unlink()
#include <fcntl.h>       // Include for mkstemp()
#include "htslib/sam.h"  // Include the necessary header for sam_hdr_t

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    // Check if size is sufficient to create a valid sam_hdr_t object
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to write the data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Open the SAM/BAM file using htslib
    samFile *in = sam_open(tmpl, "r");
    if (in == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Read the header from the SAM/BAM file
    sam_hdr_t *hdr = sam_hdr_read(in);
    if (hdr == NULL) {
        sam_close(in);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    int nref = sam_hdr_nref(hdr);

    // Clean up
    sam_hdr_destroy(hdr);
    sam_close(in);
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

    LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
