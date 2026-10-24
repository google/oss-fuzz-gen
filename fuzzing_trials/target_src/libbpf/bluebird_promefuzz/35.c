#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include "/src/libbpf/src/libbpf_legacy.h"
#include "libbpf.h"

#define DUMMY_FILE_PATH "./dummy_file"

static int custom_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Step 1: Set a custom print function
    libbpf_set_print(custom_print_fn);

    // Step 2: Open a BPF object from memory
    struct bpf_object_open_opts opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .object_name = "fuzzed_object",
    };

    struct bpf_object *obj = bpf_object__open_mem(Data, Size, &opts);

    // Step 3: Check for errors using deprecated function

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_object__open_mem to perf_buffer__new_raw
    long ret_libbpf_get_error_phigg = libbpf_get_error((const void *)Data);
    if (ret_libbpf_get_error_phigg < 0){
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from libbpf_get_error to libbpf_unregister_prog_handler
    int ret_libbpf_unregister_prog_handler_oahvu = libbpf_unregister_prog_handler((int )ret_libbpf_get_error_phigg);
    if (ret_libbpf_unregister_prog_handler_oahvu < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    long ret_libbpf_get_error_kgfem = libbpf_get_error((const void *)Data);
    if (ret_libbpf_get_error_kgfem < 0){
    	return 0;
    }
    struct perf_buffer_raw_opts gwzzgnlu;
    memset(&gwzzgnlu, 0, sizeof(gwzzgnlu));
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    struct perf_buffer* ret_perf_buffer__new_raw_xfxtr = perf_buffer__new_raw((int )ret_libbpf_get_error_phigg, (size_t )ret_libbpf_get_error_kgfem, NULL, NULL, (void *)obj, &gwzzgnlu);
    if (ret_perf_buffer__new_raw_xfxtr == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    long err = libbpf_get_error(obj);
    if (err) {
        // Handle error (deprecated function, just for demonstration)
        fprintf(stderr, "Error opening BPF object: %ld\n", err);
        return 0;
    }

    // Step 4: Close the BPF object if it was successfully opened
    if (obj != NULL) {
        bpf_object__close(obj);
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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
