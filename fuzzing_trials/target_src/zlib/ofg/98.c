#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Create a temporary file to write the data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the file with gzopen
    gzFile gz_file = gzopen(tmpl, "rb");
    if (gz_file == NULL) {
        remove(tmpl);
        return 0;
    }

    // Try flushing the gzFile
    int flush_result = gzflush(gz_file, Z_SYNC_FLUSH);

    // Close the gzFile
    gzclose(gz_file);

    // Clean up the temporary file
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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
