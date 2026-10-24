#include <stdint.h>
#include <stdlib.h>
#include <htslib/hts.h>
#include <htslib/kstring.h>  // Added for kstring_t
#include <htslib/kseq.h>     // Added for KS_SEP_LINE
#include <stdio.h>           // Added for file operations

int LLVMFuzzerTestOneInput_219(const uint8_t *data, size_t size) {
    // Create a temporary file to use as input for hts_open
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        return 0;  // If temp file creation fails, return early
    }

    // Write the fuzzer data to the temporary file
    fwrite(data, 1, size, temp_file);
    rewind(temp_file);  // Reset file pointer to the beginning

    // Open the temporary file using hts_open
    htsFile *file = hts_open("-", "r");
    if (file == NULL) {
        fclose(temp_file);
        return 0;  // If file opening fails, clean up and return early
    }

    // Perform some basic operations with the file to fuzz
    kstring_t str = {0, 0, NULL};
    if (hts_getline(file, KS_SEP_LINE, &str) < 0) {
        hts_close(file);
        fclose(temp_file);
        return 0;  // If reading fails, clean up and return early
    }

    // Clean up
    hts_close(file);
    fclose(temp_file);
    free(str.s);

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

    LLVMFuzzerTestOneInput_219(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
