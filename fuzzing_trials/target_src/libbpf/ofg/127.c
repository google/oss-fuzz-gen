#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libbpf/src/libbpf.h"
#include <linux/bpf.h>

int LLVMFuzzerTestOneInput_127(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for a valid input
    if (size < sizeof(enum bpf_prog_type) + sizeof(enum bpf_attach_type)) {
        return 0;
    }

    // Extract values from data
    const char *prog_name = "test_prog";
    enum bpf_prog_type prog_type = (enum bpf_prog_type)(data[0] % (BPF_PROG_TYPE_SYSCALL + 1));
    enum bpf_attach_type attach_type = (enum bpf_attach_type)(data[1] % (BPF_PERF_EVENT + 1));

    struct libbpf_prog_handler_opts opts;
    opts.sz = sizeof(struct libbpf_prog_handler_opts);

    // Call the function-under-test
    int result = libbpf_register_prog_handler(prog_name, prog_type, attach_type, &opts);

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

    LLVMFuzzerTestOneInput_127(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
