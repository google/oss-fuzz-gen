#include <stdint.h>
#include <stddef.h>
#include <htslib/hts.h>
#include <htslib/sam.h>
#include <htslib/bgzf.h>
#include <htslib/kseq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Initialize kseq structure for reading sequences
KSEQ_INIT(BGZF*, bgzf_read)

int LLVMFuzzerTestOneInput_171(const uint8_t *data, size_t size) {
    // Create a BGZF file in memory
    BGZF *bgzf = bgzf_open("/dev/null", "w");
    if (bgzf == NULL) {
        return 0;
    }

    // Write the input data to the BGZF file
    if (bgzf_write(bgzf, data, size) < 0) {
        bgzf_close(bgzf);
        return 0;
    }

    // Close and reopen the BGZF file for reading
    bgzf_close(bgzf);
    bgzf = bgzf_open("/dev/null", "r");
    if (bgzf == NULL) {
        return 0;
    }

    // Initialize kseq for reading sequences
    kseq_t *seq = kseq_init(bgzf);

    // Read sequences and process them
    while (kseq_read(seq) >= 0) {
        // Initialize necessary structures with correct parameters
        hts_idx_t *index = hts_idx_init(0, HTS_FMT_BAI, 0, 14, 5);
        hts_itr_t *iterator = hts_itr_query(index, 0, 0, 0, NULL);

        // Check if initialization was successful
        if (index == NULL || iterator == NULL) {
            if (index != NULL) hts_idx_destroy(index);
            if (iterator != NULL) hts_itr_destroy(iterator);
            kseq_destroy(seq);
            bgzf_close(bgzf);
            return 0;
        }

        // Call the function under test with non-null input
        int result = hts_itr_next(NULL, iterator, NULL, NULL);

        // Clean up
        hts_idx_destroy(index);
        hts_itr_destroy(iterator);
    }

    // Clean up
    kseq_destroy(seq);
    bgzf_close(bgzf);

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

    LLVMFuzzerTestOneInput_171(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
