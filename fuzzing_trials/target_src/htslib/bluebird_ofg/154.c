#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "htslib/sam.h"
#include "htslib/hts.h"
#include <string.h>

int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a meaningful fuzz input
    if (size < sizeof(bam1_t)) {
        return 0;
    }

    // Create a temporary file for htsFile
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Open the temporary file as an htsFile
    htsFile *hts_fp = hts_open(tmpl, "wb");
    if (!hts_fp) {
        unlink(tmpl); // Ensure the temporary file is removed
        return 0;
    }

    // Initialize a sam_hdr_t
    sam_hdr_t *sam_hdr = sam_hdr_init();
    if (!sam_hdr) {
        hts_close(hts_fp);
        unlink(tmpl); // Ensure the temporary file is removed
        return 0;
    }

    // Initialize a bam1_t
    bam1_t *bam_record = bam_init1();
    if (!bam_record) {
        sam_hdr_destroy(sam_hdr);
        hts_close(hts_fp);
        unlink(tmpl); // Ensure the temporary file is removed
        return 0;
    }

    // Allocate memory for bam1_t data and copy the input data
    bam_record->data = (uint8_t *)malloc(size);
    if (!bam_record->data) {
        bam_destroy1(bam_record);
        sam_hdr_destroy(sam_hdr);
        hts_close(hts_fp);
        unlink(tmpl); // Ensure the temporary file is removed
        return 0;
    }
    memcpy(bam_record->data, data, size);
    bam_record->l_data = size;

    // Call the function-under-test
    if (sam_write1(hts_fp, sam_hdr, bam_record) < 0) {
        // Handle the error if writing fails
        free(bam_record->data);  // Free the allocated memory
        bam_destroy1(bam_record);
        sam_hdr_destroy(sam_hdr);
        hts_close(hts_fp);
        unlink(tmpl); // Ensure the temporary file is removed
        return 0;
    }

    // Clean up
    free(bam_record->data);  // Free the allocated memory
    bam_record->data = NULL; // Prevent double-free by nullifying the pointer
    bam_destroy1(bam_record);
    sam_hdr_destroy(sam_hdr);
    hts_close(hts_fp);
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

    LLVMFuzzerTestOneInput_154(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
