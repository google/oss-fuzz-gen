#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "/src/libbpf/src/bpf.h"
#include "libbpf.h"

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
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
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function bpf_object__load with bpf_object__prepare
    if (bpf_object__prepare(obj) < 0) {
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
        bpf_object__close(obj);
        return 0;
    }

    // Get the first program in the BPF object

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_object__open_mem to bpf_object__btf
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    struct btf* ret_bpf_object__btf_chntd = bpf_object__btf(obj);
    if (ret_bpf_object__btf_chntd == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return 0;
    }

    // Call the function-under-test

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_object__next_program to bpf_program__attach_ksyscall

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_object__next_program to bpf_program__set_autoattach
    // Ensure dataflow is valid (i.e., non-null)
    if (!prog) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_object__next_program to bpf_program__set_attach_target
    long ret_libbpf_get_error_uiftk = libbpf_get_error((const void *)"r");
    if (ret_libbpf_get_error_uiftk < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!prog) {
    	return 0;
    }
    int ret_bpf_program__set_attach_target_bxshf = bpf_program__set_attach_target(prog, (int )ret_libbpf_get_error_uiftk, (const char *)data);
    if (ret_bpf_program__set_attach_target_bxshf < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    bpf_program__set_autoattach(prog, 1);
    // End mutation: Producer.APPEND_MUTATOR
    
    const char euavhiii[1024] = "uriqh";
    // Ensure dataflow is valid (i.e., non-null)
    if (!prog) {
    	return 0;
    }
    struct bpf_link* ret_bpf_program__attach_ksyscall_jujzx = bpf_program__attach_ksyscall(prog, euavhiii, NULL);
    if (ret_bpf_program__attach_ksyscall_jujzx == NULL){
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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
