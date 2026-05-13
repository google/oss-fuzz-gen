#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include "/src/libbpf/src/libbpf.h"

// Define a custom print function to be used with libbpf_set_print
int custom_print_fn_133(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient to create a valid function pointer
    if (size < sizeof(libbpf_print_fn_t)) {
        return 0;
    }

    // Cast the data to a function pointer of type libbpf_print_fn_t
    libbpf_print_fn_t print_fn = (libbpf_print_fn_t)(uintptr_t)data;

    // Set the custom print function using libbpf_set_print
    libbpf_print_fn_t old_print_fn = libbpf_set_print(print_fn);

    // Restore the original print function after testing
    libbpf_set_print(old_print_fn);

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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
