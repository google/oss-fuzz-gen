#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>
#include <stdio.h>
#include <unistd.h>   // Include unistd.h for close() and mkstemp()

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    gzFile file;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0;
    }

    // Open the temporary file with gzdopen
    file = gzdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }

    // Ensure size is not zero to avoid gzwrite with zero length
    if (size > 0) {
        // Call gzwrite with the data and size
        gzwrite(file, (const void*)data, (unsigned int)size);
    }

    // Close the gzFile
    gzclose(file);

    // Remove the temporary file
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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
