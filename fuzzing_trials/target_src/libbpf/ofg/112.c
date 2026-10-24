#include "/src/libbpf/src/libbpf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct bpf_object *obj = NULL;
    char filename[] = "/tmp/fuzz_bpf_prog.o";
    int fd;

    if (size < 1) {
        return 0;
    }

    // Create a temporary file to store the fuzz data
    fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        remove(filename);
        return 0;
    }

    close(fd);

    // Open the BPF object file
    obj = bpf_object__open_file(filename, NULL);
    if (!obj) {
        remove(filename);
        return 0;
    }

    // Load the BPF object
    if (bpf_object__load(obj) != 0) {
        bpf_object__close(obj);
        remove(filename);
        return 0;
    }

    // Get the first program from the BPF object
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        remove(filename);
        return 0;
    }

    // Call the function-under-test
    link = bpf_program__attach(prog);

    // Clean up
    if (link) {
        bpf_link__destroy(link);
    }
    bpf_object__close(obj);
    remove(filename);

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

    LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
