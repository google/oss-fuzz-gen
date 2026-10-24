#include <stdint.h>
#include <stddef.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for extracting an integer value
    if (size < sizeof(int)) {
        return 0;
    }

    // Create an htsFile object
    htsFile *file = hts_open("test.bam", "wb");
    if (file == NULL) {
        return 0;
    }

    // Extract an integer from the data
    int num_threads = *(const int *)data;

    // Call the function-under-test
    hts_set_threads(file, num_threads);

    // Close the htsFile
    hts_close(file);

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

    LLVMFuzzerTestOneInput_23(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
