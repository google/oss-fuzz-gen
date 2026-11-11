// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// libbpf_get_error at libbpf.c:11207:6 in libbpf_legacy.h
// bpf_object__load at libbpf.c:9040:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_program__attach_tracepoint at libbpf.c:13132:18 in libbpf.h
// bpf_program__attach_tracepoint_opts at libbpf.c:13099:18 in libbpf.h
// bpf_program__attach_raw_tracepoint at libbpf.c:13208:18 in libbpf.h
// bpf_program__attach_raw_tracepoint_opts at libbpf.c:13172:1 in libbpf.h
// bpf_program__attach_ksyscall at libbpf.c:11913:18 in libbpf.h
// bpf_program__attach_kprobe_multi_opts at libbpf.c:12153:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>
#include <errno.h>

static void detach_and_dealloc(struct bpf_link *link) {
    if (link) {
        bpf_link__destroy(link);
    }
}

int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size) {
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct bpf_object *obj = NULL;
    char tp_category[256];
    char tp_name[256];
    struct bpf_tracepoint_opts tp_opts = { .sz = sizeof(tp_opts), .bpf_cookie = 0 };
    struct bpf_raw_tracepoint_opts raw_tp_opts = { .sz = sizeof(raw_tp_opts), .cookie = 0 };
    struct bpf_ksyscall_opts ksyscall_opts = { .sz = sizeof(ksyscall_opts), .bpf_cookie = 0, .retprobe = false };
    struct bpf_kprobe_multi_opts kprobe_multi_opts = { .sz = sizeof(kprobe_multi_opts), .cnt = 0 };

    // Ensure that the input data is large enough to avoid buffer overflows
    if (Size < 2) return 0;

    // Initialize tracepoint category and name
    size_t tp_category_len = Data[0] % 255;
    size_t tp_name_len = Data[1] % 255;
    if (Size < 2 + tp_category_len + tp_name_len) return 0;
    memcpy(tp_category, Data + 2, tp_category_len);
    tp_category[tp_category_len] = '\0';
    memcpy(tp_name, Data + 2 + tp_category_len, tp_name_len);
    tp_name[tp_name_len] = '\0';

    // Load a BPF object file to get a valid bpf_program
    obj = bpf_object__open_file("dummy_bpf_program.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 0;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 0;
    }

    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "Failed to get BPF program\n");
        bpf_object__close(obj);
        return 0;
    }

    // Fuzz bpf_program__attach_tracepoint
    link = bpf_program__attach_tracepoint(prog, tp_category, tp_name);
    detach_and_dealloc(link);

    // Fuzz bpf_program__attach_tracepoint_opts
    link = bpf_program__attach_tracepoint_opts(prog, tp_category, tp_name, &tp_opts);
    detach_and_dealloc(link);

    // Fuzz bpf_program__attach_raw_tracepoint
    link = bpf_program__attach_raw_tracepoint(prog, tp_name);
    detach_and_dealloc(link);

    // Fuzz bpf_program__attach_raw_tracepoint_opts
    link = bpf_program__attach_raw_tracepoint_opts(prog, tp_name, &raw_tp_opts);
    detach_and_dealloc(link);

    // Fuzz bpf_program__attach_ksyscall
    link = bpf_program__attach_ksyscall(prog, tp_name, &ksyscall_opts);
    detach_and_dealloc(link);

    // Fuzz bpf_program__attach_kprobe_multi_opts
    link = bpf_program__attach_kprobe_multi_opts(prog, tp_name, &kprobe_multi_opts);
    if (!link && errno == EINVAL) {
        // Handle expected invalid argument error
    } else {
        detach_and_dealloc(link);
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

        LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    