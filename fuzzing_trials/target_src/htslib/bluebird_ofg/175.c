#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "htslib/hts.h"
#include "htslib/sam.h"

// Function to simulate a valid htsFile and header for testing
htsFile* create_dummy_htsfile() {
    return hts_open("-", "r"); // Open a dummy file stream for reading
}

bam_hdr_t* create_dummy_header() {
    bam_hdr_t *hdr = bam_hdr_init();
    hdr->n_targets = 1;
    hdr->target_len = (uint32_t*)malloc(sizeof(uint32_t));
    hdr->target_len[0] = 1000; // Dummy length
    hdr->target_name = (char**)malloc(sizeof(char*));
    hdr->target_name[0] = strdup("dummy"); // Dummy name
    return hdr;
}

int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Create a dummy htsFile and header
    htsFile *hts_fp = create_dummy_htsfile();
    bam_hdr_t *hdr = create_dummy_header();

    if (!hts_fp || !hdr) {
        return 0;
    }

    // Initialize an hts_itr_t structure using hts_itr_query
    hts_itr_t *itr = hts_itr_query(NULL, 0, data[0] % 1000, data[1] % 1000, 0);
    if (!itr) {
        bam_hdr_destroy(hdr);
        hts_close(hts_fp);
        return 0;
    }

    // Simulate using the data in some meaningful way
    itr->beg = data[0] % 1000; // Example modification
    itr->end = data[1] % 1000; // Example modification

    // Call the function-under-test
    hts_itr_destroy(itr);

    // Clean up
    bam_hdr_destroy(hdr);
    hts_close(hts_fp);

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

    LLVMFuzzerTestOneInput_175(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
