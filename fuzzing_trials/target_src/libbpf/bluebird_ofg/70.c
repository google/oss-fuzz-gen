#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "/src/libbpf/src/bpf.h"
#include "/src/libbpf/src/bpf.h"
#include "libbpf.h"

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract a bpf_prog_type value
    if (size < sizeof(enum bpf_prog_type)) {
        return 0;
    }

    // Cast the input data to a bpf_prog_type
    enum bpf_prog_type prog_type = *(const enum bpf_prog_type *)data;

    // Call the function-under-test
    const char *result = libbpf_bpf_prog_type_str(prog_type);

    // Optionally, you can do something with the result, like logging or checking
    // For this harness, we simply ignore the result as we're focusing on fuzzing
    (void)result;

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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
