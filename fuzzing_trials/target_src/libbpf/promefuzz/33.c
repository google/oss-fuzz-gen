// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// libbpf_find_vmlinux_btf_id at libbpf.c:10506:5 in libbpf.h
// libbpf_attach_type_by_name at libbpf.c:10659:5 in libbpf.h
// bpf_program__expected_attach_type at libbpf.c:9764:22 in libbpf.h
// libbpf_prog_type_by_name at libbpf.c:10263:5 in libbpf.h
// libbpf_strerror at libbpf_utils.c:47:5 in libbpf.h
// libbpf_num_possible_cpus at libbpf.c:14447:5 in libbpf.h
// libbpf_strerror at libbpf_utils.c:47:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>

static const char *dummy_file_path = "./dummy_file";

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(dummy_file_path, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a buffer for libbpf_strerror
    char error_buffer[128];

    // Ensure null-terminated strings for APIs expecting C strings
    char *name_buffer = (char *)malloc(Size + 1);
    if (!name_buffer) return 0;
    memcpy(name_buffer, Data, Size);
    name_buffer[Size] = '\0';

    // 1. Test libbpf_find_vmlinux_btf_id
    enum bpf_attach_type attach_type = (enum bpf_attach_type)(Data[0] % __MAX_BPF_ATTACH_TYPE);
    libbpf_find_vmlinux_btf_id(name_buffer, attach_type);

    // 2. Test libbpf_attach_type_by_name
    enum bpf_attach_type attach_type_result;
    libbpf_attach_type_by_name(name_buffer, &attach_type_result);

    // 3. Test bpf_program__expected_attach_type
    struct bpf_program {
        char *name;
        char *sec_name;
        size_t sec_idx;
        enum bpf_prog_type type;
        enum bpf_attach_type expected_attach_type;
    } prog;
    prog.expected_attach_type = attach_type;
    bpf_program__expected_attach_type(&prog);

    // 4. Test libbpf_prog_type_by_name
    enum bpf_prog_type prog_type_result;
    libbpf_prog_type_by_name(name_buffer, &prog_type_result, &attach_type_result);

    // 5. Test libbpf_strerror
    int err_code = (int)Data[0];
    libbpf_strerror(err_code, error_buffer, sizeof(error_buffer));

    // 6. Test libbpf_num_possible_cpus
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) {
        libbpf_strerror(num_cpus, error_buffer, sizeof(error_buffer));
    }

    // Write data to dummy file
    write_dummy_file(Data, Size);

    free(name_buffer);
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

        LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    