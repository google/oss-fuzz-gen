#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {
    #include "magic.h"
}

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    struct magic_set *magic;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;
    FILE *fp;

    // Initialize magic_set
    magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Create a temporary file and write the input data to it
    fd = mkstemp(tmpl);
    if (fd == -1) {
        magic_close(magic);
        return 0;
    }
    fp = fdopen(fd, "wb");
    if (fp == NULL) {
        close(fd);
        magic_close(magic);
        return 0;
    }
    fwrite(data, 1, size, fp);
    fclose(fp);

    // Call the function-under-test
    magic_list(magic, tmpl);

    // Clean up
    unlink(tmpl);
    magic_close(magic);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
