// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// bpf_object__prepare at libbpf.c:9035:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__load at libbpf.c:9040:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__pin_programs at libbpf.c:9357:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__pin_maps at libbpf.c:9279:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__load_skeleton at libbpf.c:14618:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__token_fd at libbpf.c:9552:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static struct bpf_object *open_bpf_object(const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return NULL;
    }

    if (write(fd, Data, Size) != Size) {
        close(fd);
        return NULL;
    }

    lseek(fd, 0, SEEK_SET);

    struct bpf_object_open_opts open_opts = {};
    struct bpf_object *obj = bpf_object__open_file("./dummy_file", &open_opts);
    close(fd);
    return obj;
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    struct bpf_object *obj = open_bpf_object(Data, Size);
    if (!obj) {
        return 0;
    }

    int ret = bpf_object__prepare(obj);
    if (ret < 0) {
        bpf_object__close(obj);
        return 0;
    }

    ret = bpf_object__load(obj);
    if (ret < 0) {
        bpf_object__close(obj);
        return 0;
    }

    ret = bpf_object__pin_programs(obj, "/sys/fs/bpf");
    if (ret < 0) {
        bpf_object__close(obj);
        return 0;
    }

    ret = bpf_object__pin_maps(obj, "/sys/fs/bpf");
    if (ret < 0) {
        bpf_object__close(obj);
        return 0;
    }

    struct bpf_object_skeleton skel = {
        .sz = sizeof(struct bpf_object_skeleton),
        .obj = &obj,
    };
    ret = bpf_object__load_skeleton(&skel);
    if (ret < 0) {
        bpf_object__close(obj);
        return 0;
    }

    int token_fd = bpf_object__token_fd(obj);
    if (token_fd < 0) {
        bpf_object__close(obj);
        return 0;
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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    