#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "htslib/hfile.h" // Assuming the function is part of the HTSlib library

int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    hFILE *file = NULL;

    // Create a temporary file and write the input data to it
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *fp = fdopen(fd, "wb");
    if (fp == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, fp);
    fclose(fp);

    // Open the temporary file with htslib's hfile API
    file = hopen(tmpl, "rb");
    if (file == NULL) {
        remove(tmpl);
        return 0;
    }

    // Read data from the hfile to ensure code paths are exercised
    char buffer[1024];
    ssize_t bytes_read;
    while ((bytes_read = hread(file, buffer, sizeof(buffer))) > 0) {
        // Process the buffer to simulate usage and ensure coverage
        // Example: print the first few bytes of the buffer
        for (ssize_t i = 0; i < bytes_read && i < 10; ++i) {
            printf("%02x ", (unsigned char)buffer[i]);
        }
        printf("\n");
    }

    // Clean up
    hclose(file);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_160(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
