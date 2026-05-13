#include <sys/stat.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "libbpf.h"

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Create a fake bpf_object with the input data
    struct bpf_object *bpf_obj = bpf_object__open_mem(data, size, NULL);
    if (!bpf_obj) {
        return 0;
    }

    // Call the function-under-test

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_object__open_mem to bpf_object__load
    // Ensure dataflow is valid (i.e., non-null)
    if (!bpf_obj) {
    	return 0;
    }
    int ret_bpf_object__load_zjtpu = bpf_object__load(bpf_obj);
    if (ret_bpf_object__load_zjtpu < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    struct btf *btf_obj = bpf_object__btf(bpf_obj);

    // Clean up resources
    bpf_object__close(bpf_obj);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
