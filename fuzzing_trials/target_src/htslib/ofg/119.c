#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    hts_opt *options = NULL;

    // Ensure the input data is null-terminated for a valid C string
    char *opt_str = (char *)malloc(size + 1);
    if (opt_str == NULL) {
        return 0;
    }

    memcpy(opt_str, data, size);
    opt_str[size] = '\0';  // Null-terminate the string

    // Call the function-under-test
    int result = hts_opt_add(&options, opt_str);

    // Clean up
    free(opt_str);
    hts_opt_free(options);

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

    LLVMFuzzerTestOneInput_119(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
