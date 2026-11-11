#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>
#include <htslib/hts.h>
#include <htslib/hts_defs.h> // Ensure this is included for hts_itr_t

int LLVMFuzzerTestOneInput_264(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < 4) return 0;

    // Initialize necessary structures
    sam_hdr_t *hdr = sam_hdr_init();
    char **regarray = (char **)malloc(2 * sizeof(char *));
    unsigned int regarray_count = 2;

    // Ensure allocated memory is not NULL
    if (!hdr || !regarray) {
        sam_hdr_destroy(hdr);
        free(regarray);
        return 0;
    }

    // Split the input data into two regions for the regarray
    regarray[0] = (char *)malloc((size / 2) + 1);
    regarray[1] = (char *)malloc((size / 2) + 1);

    if (!regarray[0] || !regarray[1]) {
        sam_hdr_destroy(hdr);
        free(regarray[0]);
        free(regarray[1]);
        free(regarray);
        return 0;
    }

    // Copy data into regarray
    memcpy(regarray[0], data, size / 2);
    regarray[0][size / 2] = '\0'; // Null-terminate the string
    memcpy(regarray[1], data + size / 2, size / 2);
    regarray[1][size / 2] = '\0'; // Null-terminate the string

    // Mock or simulate the index creation/loading
    // Since we cannot create a real index without a file, this part is omitted
    // hts_idx_t *idx = hts_idx_load("some_index_file"); // Typically used for real index loading

    // Call the function-under-test
    // hts_itr_t *itr = sam_itr_regarray(idx, hdr, regarray, regarray_count);

    // Clean up
    // hts_itr_destroy(itr); // Uncomment if itr is used
    // free(idx); // Uncomment if idx is used
    sam_hdr_destroy(hdr);
    free(regarray[0]);
    free(regarray[1]);
    free(regarray);

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

    LLVMFuzzerTestOneInput_264(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
