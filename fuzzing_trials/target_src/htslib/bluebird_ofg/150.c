#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> // for close() and unlink()
#include <fcntl.h>  // for mkstemp()
#include "/src/htslib/ref_cache/types.h" // for ssize_t
#include "htslib/sam.h"
#include "htslib/hts.h"

int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    // Create a temporary file to store the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Open the temporary file as an htsFile
    htsFile *hts_file = hts_open(tmpl, "r");
    if (hts_file == NULL) {
        return 0;
    }

    // Initialize the sam_hdr_t and bam1_t structures
    sam_hdr_t *header = sam_hdr_read(hts_file);
    if (header == NULL) {
        hts_close(hts_file);
        return 0;
    }

    bam1_t *b = bam_init1();
    if (b == NULL) {
        sam_hdr_destroy(header);
        hts_close(hts_file);
        return 0;
    }

    // Call the function under test
    sam_read1(hts_file, header, b);

    // Clean up
    bam_destroy1(b);
    sam_hdr_destroy(header);
    hts_close(hts_file);
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

    LLVMFuzzerTestOneInput_150(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
