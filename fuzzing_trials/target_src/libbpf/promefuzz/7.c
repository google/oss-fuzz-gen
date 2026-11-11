// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_linker__new at linker.c:227:20 in libbpf.h
// bpf_linker__add_file at linker.c:518:5 in libbpf.h
// bpf_linker__add_fd at linker.c:541:5 in libbpf.h
// bpf_linker__finalize at linker.c:2752:5 in libbpf.h
// bpf_linker__free at linker.c:190:6 in libbpf.h
// bpf_linker__new_fd at linker.c:269:20 in libbpf.h
// bpf_linker__add_file at linker.c:518:5 in libbpf.h
// bpf_linker__add_fd at linker.c:541:5 in libbpf.h
// bpf_linker__finalize at linker.c:2752:5 in libbpf.h
// bpf_linker__free at linker.c:190:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libbpf.h>

static struct bpf_linker_opts default_opts = {
    .sz = sizeof(struct bpf_linker_opts),
};

static void write_dummy_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file) {
        fputs("dummy content", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy file to use with bpf_linker__new and bpf_linker__add_file
    const char *dummy_filename = "./dummy_file";
    write_dummy_file(dummy_filename);

    // Convert first byte of data to a file descriptor
    int fd = open(dummy_filename, O_RDONLY);
    if (fd < 0) return 0;

    struct bpf_linker *linker = NULL;
    struct bpf_linker_opts opts = default_opts;

    // Fuzz bpf_linker__new
    linker = bpf_linker__new(dummy_filename, &opts);
    if (linker) {
        // Fuzz bpf_linker__add_file
        bpf_linker__add_file(linker, dummy_filename, NULL);

        // Fuzz bpf_linker__add_fd
        bpf_linker__add_fd(linker, fd, NULL);

        // Fuzz bpf_linker__finalize
        bpf_linker__finalize(linker);

        // Free the linker
        bpf_linker__free(linker);
    }

    // Fuzz bpf_linker__new_fd
    linker = bpf_linker__new_fd(fd, &opts);
    if (linker) {
        // Fuzz bpf_linker__add_file
        bpf_linker__add_file(linker, dummy_filename, NULL);

        // Fuzz bpf_linker__add_fd
        bpf_linker__add_fd(linker, fd, NULL);

        // Fuzz bpf_linker__finalize
        bpf_linker__finalize(linker);

        // Free the linker
        bpf_linker__free(linker);
    }

    close(fd);
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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    