// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_program__attach_perf_event at libbpf.c:11489:18 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_cgroup at libbpf.c:13354:1 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_netns at libbpf.c:13360:1 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_netkit at libbpf.c:13441:1 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_xdp at libbpf.c:13371:18 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>
#include <fcntl.h>
#include <unistd.h>

static int create_dummy_fd() {
    int fd = open("./dummy_file", O_CREAT | O_RDWR, 0644);
    if (fd >= 0) {
        write(fd, "dummy", 5);
        lseek(fd, 0, SEEK_SET);
    }
    return fd;
}

int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size) {
    int pfd, cgroup_fd, netns_fd, ifindex;
    struct bpf_link *link;
    struct bpf_netkit_opts opts = {
        .sz = sizeof(opts),
        .flags = 0,
    };
    struct bpf_program *prog = NULL;
    struct bpf_object *obj = bpf_object__open_file("./dummy_file", NULL);
    if (obj) {
        prog = bpf_object__next_program(obj, NULL);
    }

    if (prog) {
        // Fuzz bpf_program__attach_perf_event
        pfd = create_dummy_fd();
        if (pfd >= 0) {
            link = bpf_program__attach_perf_event(prog, pfd);
            if (link) {
                bpf_link__detach(link);
                bpf_link__destroy(link);
            }
            close(pfd);
        }

        // Fuzz bpf_program__attach_cgroup
        cgroup_fd = create_dummy_fd();
        if (cgroup_fd >= 0) {
            link = bpf_program__attach_cgroup(prog, cgroup_fd);
            if (link) {
                bpf_link__detach(link);
                bpf_link__destroy(link);
            }
            close(cgroup_fd);
        }

        // Fuzz bpf_program__attach_netns
        netns_fd = create_dummy_fd();
        if (netns_fd >= 0) {
            link = bpf_program__attach_netns(prog, netns_fd);
            if (link) {
                bpf_link__detach(link);
                bpf_link__destroy(link);
            }
            close(netns_fd);
        }

        // Fuzz bpf_program__attach_netkit
        ifindex = (Size > 0) ? Data[0] % 256 : 0;
        link = bpf_program__attach_netkit(prog, ifindex, &opts);
        if (link) {
            bpf_link__detach(link);
            bpf_link__destroy(link);
        }

        // Fuzz bpf_program__attach_xdp
        ifindex = (Size > 0) ? Data[0] % 256 : 0;
        link = bpf_program__attach_xdp(prog, ifindex);
        if (link) {
            bpf_link__detach(link);
            bpf_link__destroy(link);
        }
    }

    if (obj) {
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

        LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    