#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "zlib.h"
#include "sys/types.h"
#include "sys/stat.h" // Include this header for off_t

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the file with gzopen
    gzFile gzfile = gzopen(tmpl, "rb");
    if (!gzfile) {
        remove(tmpl);
        return 0;
    }

    // Define an offset and whence for gzseek
    // Use the first few bytes of the data to determine the offset and whence
    off_t offset = 0;
    int whence = SEEK_SET;
    if (size >= sizeof(off_t) + 1) {
        offset = *((off_t *)data);
        whence = data[sizeof(off_t)] % 3; // Map to SEEK_SET, SEEK_CUR, SEEK_END
    }

    // Call the function-under-test
    off_t result = gzseek(gzfile, offset, whence);

    // Attempt to read some data after seeking
    char buffer[1024];
    int bytesRead = gzread(gzfile, buffer, sizeof(buffer));

    // Clean up
    gzclose(gzfile);
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
