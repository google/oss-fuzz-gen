#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free
#include "htslib/sam.h"
#include "htslib/hts.h"
#include "/src/htslib/htslib/hts_defs.h"
#include "/src/htslib/htslib/hts_log.h"

// Remove the extern "C" linkage specification for C++
// since this is a C code file
int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for string usage
    char *query_string = (char *)malloc(size + 1);
    if (!query_string) {
        return 0;
    }
    memcpy(query_string, data, size);
    query_string[size] = '\0';

    // Initialize dummy sam_hdr_t
    sam_hdr_t *dummy_hdr = sam_hdr_init();
    if (!dummy_hdr) {
        free(query_string);
        return 0;
    }

    // Create a minimal valid hts_idx_t object
    // For the purposes of this example, we will simulate creating a minimal index
    // In a real-world scenario, this would involve creating or loading an actual index
    // Adjust the number of arguments to match the function signature
    hts_idx_t *dummy_idx = hts_idx_init(1, HTS_FMT_CSI, 0, 0, 0);

    // Call the function-under-test
    if (dummy_idx) {
        hts_itr_t *itr = sam_itr_querys(dummy_idx, dummy_hdr, query_string);

        // Clean up
        if (itr) hts_itr_destroy(itr);
        hts_idx_destroy(dummy_idx);
    }

    free(query_string);
    sam_hdr_destroy(dummy_hdr);

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

    LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
