#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>
#include <htslib/bgzf.h>
#include <htslib/sam.h> // Include for BAM/SAM file handling

int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    // Write the input data to a temporary file
    char tmp_filename[] = "/tmp/fuzz_inputXXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        return 0;
    }
    write(fd, data, size);
    close(fd);

    // Open the temporary file using HTSlib
    htsFile *hts_file = hts_open(tmp_filename, "r");
    if (hts_file == NULL) {
        unlink(tmp_filename);
        return 0;
    }

    // Read the header
    bam_hdr_t *header = sam_hdr_read(hts_file);
    if (header == NULL) {
        hts_close(hts_file);
        unlink(tmp_filename);
        return 0;
    }

    // Initialize a BAM record
    bam1_t *b = bam_init1();
    if (b == NULL) {
        bam_hdr_destroy(header);
        hts_close(hts_file);
        unlink(tmp_filename);
        return 0;
    }

    // Read records from the file
    while (sam_read1(hts_file, header, b) >= 0) {
        // Process each record (this is where coverage can be increased)
    }

    // Clean up
    bam_destroy1(b);
    bam_hdr_destroy(header);
    hts_close(hts_file);
    unlink(tmp_filename);

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

    LLVMFuzzerTestOneInput_142(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
