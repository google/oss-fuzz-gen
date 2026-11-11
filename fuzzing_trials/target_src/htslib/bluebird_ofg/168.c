#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  // For mkstemp, write, close, and remove
#include "htslib/hts.h"

int LLVMFuzzerTestOneInput_168(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate an htsFile
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

    // Close the file descriptor so hts_open can open it
    close(fd);

    // Open the temporary file with hts_open
    htsFile *file = hts_open(tmpl, "r");
    if (file == NULL) {
        return 0;
    }

    // Call the function-under-test

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from hts_open to hts_set_opt
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    int ret_hts_set_opt_puzyn = hts_set_opt(file, CRAM_OPT_STORE_NM);
    if (ret_hts_set_opt_puzyn < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    hts_flush(file);

    // Clean up
    hts_close(file);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_168(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
