#include <sys/stat.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "/src/libbpf/include/uapi/linux/fcntl.h" // Include for open() flags
#include "libbpf.h"

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // If there's no data, return early
    }

    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Ensure the file is closed before attempting to open it with libbpf
    close(fd);

    // Prepare options struct
    struct bpf_object_open_opts opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .relaxed_maps = false
    };

    // Call the function-under-test
    struct bpf_object *obj = bpf_object__open_file(tmpl, &opts);
    if (!obj) {
        unlink(tmpl);
        return 0; // If object creation fails, return early
    }

    // Validate the object
    if (bpf_object__load(obj) != 0) {
        bpf_object__close(obj);
        unlink(tmpl);
        return 0; // If loading fails, return early
    }

    // Clean up

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from bpf_object__open_file to perf_buffer__new_raw using the plateau pool
    size_t page_cnt = 8;
    struct perf_event_attr *attr = (struct perf_event_attr *)data;
    perf_buffer_event_fn cb = NULL;
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    struct perf_buffer* ret_perf_buffer__new_raw_qnnuz = perf_buffer__new_raw(fd, page_cnt, attr, cb, (void *)obj, NULL);
    if (ret_perf_buffer__new_raw_qnnuz == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    bpf_object__close(obj);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
