#include <stdint.h>
#include <stddef.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    htsFile *file = hts_open("dummy.bam", "wb"); // Open a dummy file
    if (file == NULL) {
        return 0;
    }

    enum hts_fmt_option option = (enum hts_fmt_option)(data[0] % 3); // Example: Modulo to limit option values
    void *arg = (void *)(data + 1); // Use the rest of the data as the argument

    // Ensure the size is sufficient for the argument
    if (size < 2) {
        hts_close(file);
        return 0;
    }

    // Call the function-under-test
    hts_set_opt(file, option, arg);

    // Clean up
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

    LLVMFuzzerTestOneInput_31(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
