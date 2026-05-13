#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "libbpf.h"
#include "/src/libbpf/src/bpf.h"
#include "/src/libbpf/src/bpf.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "/src/libbpf/include/uapi/linux/fcntl.h"

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    struct bpf_object *obj = NULL;
    int result;

    // Create a temporary file to hold the BPF object data
    char tmpl[] = "/tmp/fuzzbpfXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        perror("write");
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Load the BPF object from the file
    obj = bpf_object__open_file(tmpl, NULL);
    if (!obj) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    result = bpf_object__load(obj);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_object__load to bpf_object__pin_maps
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    int ret_bpf_object__pin_maps_zdigq = bpf_object__pin_maps(obj, (const char *)"r");
    if (ret_bpf_object__pin_maps_zdigq < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    bpf_object__close(obj);
    close(fd);
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
