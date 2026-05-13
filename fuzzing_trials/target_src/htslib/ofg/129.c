#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // Include this for the close() and remove() functions
#include <htslib/sam.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Create a temporary file to write the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the temporary file as an htsFile
    htsFile *hts_file = hts_open(tmpl, "rb");
    if (hts_file == NULL) {
        remove(tmpl);
        return 0;
    }

    // Create a sam_hdr_t and bam1_t
    sam_hdr_t *header = sam_hdr_init();
    if (header == NULL) {
        hts_close(hts_file);
        remove(tmpl);
        return 0;
    }

    bam1_t *aln = bam_init1();
    if (aln == NULL) {
        sam_hdr_destroy(header);
        hts_close(hts_file);
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    sam_read1(hts_file, header, aln);

    // Clean up
    bam_destroy1(aln);
    sam_hdr_destroy(header);
    hts_close(hts_file);
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

    LLVMFuzzerTestOneInput_129(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
