#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include "zlib.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Compress the input data
    uLongf compressedSize = compressBound(size);

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from compressBound to crc32_combine64
    uLong ret_crc32_combine_gen_vaxdm = crc32_combine_gen(0);
    uLong ret_crc32_combine64_rgxnx = crc32_combine64(ret_crc32_combine_gen_vaxdm, compressedSize, 0);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from crc32_combine64 to deflateBound
    uLong ret_deflateBound_gbzvr = deflateBound(0, ret_crc32_combine64_rgxnx);
    // End mutation: Producer.APPEND_MUTATOR
    
    uint8_t *compressedData = (uint8_t *)malloc(compressedSize);
    if (compressedData == NULL) {
        return 0;
    }

    if (compress(compressedData, &compressedSize, data, size) != Z_OK) {
        free(compressedData);
        return 0;
    }

    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        free(compressedData);
        return 0;
    }

    // Write the compressed data to the temporary file
    if (write(fd, compressedData, compressedSize) != (ssize_t)compressedSize) {
        close(fd);
        free(compressedData);
        return 0;
    }

    // Close the file descriptor so that gzopen can open it
    close(fd);
    free(compressedData);

    // Open the file with gzopen
    gzFile gzfile = gzopen(tmpl, "rb");
    if (gzfile == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    off_t offset = gztell(gzfile);

    // Close the gzFile
    gzclose(gzfile);

    // Clean up the temporary file
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
