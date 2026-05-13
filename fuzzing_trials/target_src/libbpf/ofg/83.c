#include <stdint.h>
#include <stddef.h> // Include this for size_t
#include "/src/libbpf/src/libbpf.h" // Correct path for libbpf_num_possible_cpus

// Function prototype for the function-under-test
int libbpf_num_possible_cpus();

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Check if size is sufficient to perform meaningful operations
    if (size < sizeof(int)) {
        return 0;
    }

    // Directly call the function-under-test
    int num_cpus = libbpf_num_possible_cpus();

    // Use the result in some way to ensure the call is not optimized away
    // For demonstration, we'll perform a simple operation using the result
    if (num_cpus > 0) {
        int index = data[0] % num_cpus; // Use the input data to select a CPU index
        (void)index; // Suppress unused variable warning
    }

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

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
