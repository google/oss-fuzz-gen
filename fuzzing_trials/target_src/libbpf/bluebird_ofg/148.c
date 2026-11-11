#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "/src/libbpf/src/bpf.h"
#include "libbpf.h"

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    struct bpf_program *prog = NULL;
    int perf_event_fd = 1; // Using a non-zero file descriptor value

    // Ensure size is non-zero to avoid passing NULL data
    if (size == 0) {
        return 0;
    }

    // Create a BPF object from the input data
    struct bpf_object *obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        return 0;
    }

    // Load the BPF object
    if (bpf_object__load(obj) < 0) {
        bpf_object__close(obj);
        return 0;
    }

    // Get the first program in the BPF object
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return 0;
    }

    // Call the function-under-test

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_object__next_program to bpf_program__set_autoload
    // Ensure dataflow is valid (i.e., non-null)
    if (!prog) {
    	return 0;
    }
    int ret_bpf_program__set_autoload_ymovs = bpf_program__set_autoload(prog, 1);
    if (ret_bpf_program__set_autoload_ymovs < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    struct bpf_link *link = bpf_program__attach_perf_event(prog, perf_event_fd);

    // Clean up
    if (link) {
        bpf_link__destroy(link);
    }
    bpf_object__close(obj);

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

    LLVMFuzzerTestOneInput_148(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
