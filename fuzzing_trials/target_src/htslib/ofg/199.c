#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>

// Assuming the function under test is hts_open, which is part of HTSlib
int LLVMFuzzerTestOneInput_199(const uint8_t *data, size_t size) {
    // Allocate memory for a null-terminated string
    char *filename = (char *)malloc(size + 1);
    if (filename == NULL) {
        return 0;
    }

    // Copy the data into the filename and null-terminate it
    if (size > 0) {
        memcpy(filename, data, size);
    }
    filename[size] = '\0';

    // Fuzz the function-under-test: attempt to open a file with the given filename
    htsFile *file = hts_open(filename, "r");
    if (file != NULL) {
        hts_close(file);
    }

    // Free any allocated memory
    free(filename);

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

    LLVMFuzzerTestOneInput_199(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
