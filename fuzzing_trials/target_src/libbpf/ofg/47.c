#include <stddef.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "/src/libbpf/src/libbpf.h"

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    struct bpf_object *obj = NULL;
    struct bpf_object_open_opts opts = {};
    const char *name;

    if (size == 0) {
        return 0;
    }

    // Create a temporary file to hold the data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the BPF object from the temporary file
    obj = bpf_object__open_file(tmpl, &opts);
    if (!obj) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    name = bpf_object__name(obj);

    // Clean up
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
