#include <stdint.h>
#include <stddef.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for a pointer
    if (size < sizeof(void *)) {
        return 0;
    }

    // Cast the first part of the data to enum bpf_prog_type
    enum bpf_prog_type prog_type = (enum bpf_prog_type)data[0];

    // Use the remaining data as a pointer (casted to a const void *)
    const void *probe_data = (const void *)(data + 1);

    // Call the function-under-test
    int result = libbpf_probe_bpf_prog_type(prog_type, probe_data);

    (void)result; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
