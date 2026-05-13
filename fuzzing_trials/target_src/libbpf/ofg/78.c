#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef enum {
    BPF_ATTACH_TYPE_UNSPEC,
    BPF_ATTACH_TYPE_CGROUP_INET_INGRESS,
    BPF_ATTACH_TYPE_CGROUP_INET_EGRESS,
    BPF_ATTACH_TYPE_CGROUP_INET_SOCK_CREATE,
    BPF_ATTACH_TYPE_CGROUP_SOCK_OPS,
    BPF_ATTACH_TYPE_SK_SKB_STREAM_PARSER,
    BPF_ATTACH_TYPE_SK_SKB_STREAM_VERDICT,
    BPF_ATTACH_TYPE_CGROUP_DEVICE,
    BPF_ATTACH_TYPE_SK_MSG_VERDICT,
    BPF_ATTACH_TYPE_RAW_TRACEPOINT,
    BPF_ATTACH_TYPE_CGROUP_INET4_BIND,
    BPF_ATTACH_TYPE_CGROUP_INET6_BIND,
    BPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
    BPF_ATTACH_TYPE_CGROUP_INET6_CONNECT,
    BPF_ATTACH_TYPE_CGROUP_INET4_POST_BIND,
    BPF_ATTACH_TYPE_CGROUP_INET6_POST_BIND,
    BPF_ATTACH_TYPE_CGROUP_UDP4_SENDMSG,
    BPF_ATTACH_TYPE_CGROUP_UDP6_SENDMSG,
    BPF_ATTACH_TYPE_LIRC_MODE2,
    BPF_ATTACH_TYPE_FLOW_DISSECTOR,
    BPF_ATTACH_TYPE_CGROUP_SYSCTL,
    BPF_ATTACH_TYPE_CGROUP_UDP4_RECVMSG,
    BPF_ATTACH_TYPE_CGROUP_UDP6_RECVMSG,
    BPF_ATTACH_TYPE_MAX,
} DW_TAG_enumeration_typebpf_attach_type;

extern int libbpf_find_vmlinux_btf_id(const char *, DW_TAG_enumeration_typebpf_attach_type);

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Ensure null-terminated string
    char filename[256];
    size_t filename_size = size < 255 ? size : 255;
    for (size_t i = 0; i < filename_size; i++) {
        filename[i] = (char)data[i];
    }
    filename[filename_size] = '\0';

    // Try different enum values
    for (int attach_type = BPF_ATTACH_TYPE_UNSPEC; attach_type < BPF_ATTACH_TYPE_MAX; attach_type++) {
        libbpf_find_vmlinux_btf_id(filename, (DW_TAG_enumeration_typebpf_attach_type)attach_type);
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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
