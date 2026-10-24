#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include for close() and unlink()
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Create a temporary file to use with htsFile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *file = fdopen(fd, "w+");
    if (!file) {
        close(fd);
        return 0;
    }

    // Write the fuzz data to the temporary file
    fwrite(data, 1, size, file);
    fflush(file);
    fseek(file, 0, SEEK_SET);

    // Open the temporary file as an htsFile
    htsFile *hts = hts_open(tmpl, "r");
    if (!hts) {
        fclose(file);
        return 0;
    }

    // Read the SAM header from the fuzz data
    sam_hdr_t *hdr = sam_hdr_read(hts);
    if (!hdr) {
        hts_close(hts);
        fclose(file);
        return 0;
    }

    // Read a BAM record from the fuzz data
    bam1_t *b = bam_init1();
    if (!b) {
        sam_hdr_destroy(hdr);
        hts_close(hts);
        fclose(file);
        return 0;
    }

    if (sam_read1(hts, hdr, b) >= 0) {
        // Call the function-under-test
        sam_write1(hts, hdr, b);
    }

    // Clean up
    bam_destroy1(b);
    sam_hdr_destroy(hdr);
    hts_close(hts);
    fclose(file);
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

    LLVMFuzzerTestOneInput_35(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
