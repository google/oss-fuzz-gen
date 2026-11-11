#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "libbpf.h"
#include <unistd.h>
#include <string.h>

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Ensure there's enough data for a non-empty string and other parameters
    if (size < 2) return 0;

    // Initialize variables
    const struct bpf_program *prog = (const struct bpf_program *)data;
    pid_t pid = (pid_t)(data[0]);  // Use the first byte for pid

    // Ensure the binary path is null-terminated
    char binary_path[256];
    size_t path_length = (size - 1 < sizeof(binary_path) - 1) ? size - 1 : sizeof(binary_path) - 1;
    memcpy(binary_path, data + 1, path_length);
    binary_path[path_length] = '\0';

    // Ensure offset is within bounds
    size_t offset = (size_t)(data[0] % size);

    // Initialize bpf_uprobe_opts with default values
    struct bpf_uprobe_opts opts;
    memset(&opts, 0, sizeof(opts));

    // Call the function-under-test
    struct bpf_link *link = bpf_program__attach_uprobe_opts(prog, pid, binary_path, offset, &opts);

    // Clean up
    if (link) {
        bpf_link__destroy(link);
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

    LLVMFuzzerTestOneInput_138(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
