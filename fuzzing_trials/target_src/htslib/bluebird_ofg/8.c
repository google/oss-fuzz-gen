#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "htslib/hts.h"

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for string operations
    char *null_terminated_data = (char *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Initialize htsFormat structure
    htsFormat format;
    memset(&format, 0, sizeof(htsFormat));

    // Call the function-under-test
    int result = hts_parse_format(&format, null_terminated_data);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from hts_parse_format to hts_format_file_extension
    const char* ret_hts_format_file_extension_vtwuo = hts_format_file_extension(&format);
    if (ret_hts_format_file_extension_vtwuo == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    free(null_terminated_data);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
