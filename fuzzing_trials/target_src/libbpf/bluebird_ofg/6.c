#include <sys/stat.h>
#include <string.h>
#include "libbpf.h"
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct bpf_object *obj = NULL;
    int err;

    // Create a BPF object from the provided data
    obj = bpf_object__open_mem(data, size, NULL);
    if (!obj) {
        return 0;
    }

    // Load the BPF object
    err = bpf_object__load(obj);
    if (err) {
        bpf_object__close(obj);
        return 0;
    }

    // Get the first program in the object
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return 0;
    }

    // Attempt to attach the BPF program

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from bpf_object__next_program to bpf_program__attach_uprobe using the plateau pool
    bool retprobe = (data[0] % 2 == 0);
    pid_t pid = (pid_t)getpid();
    const char *binary_path = "/bin/ls";
    size_t offset = (size > 1) ? (size_t)data[1] : 0;
    // Ensure dataflow is valid (i.e., non-null)
    if (!prog) {
    	return 0;
    }
    struct bpf_link* ret_bpf_program__attach_uprobe_mijir = bpf_program__attach_uprobe(prog, retprobe, pid, binary_path, offset);
    if (ret_bpf_program__attach_uprobe_mijir == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    link = bpf_program__attach(prog);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
