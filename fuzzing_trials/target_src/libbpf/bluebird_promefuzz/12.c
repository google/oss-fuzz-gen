#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libbpf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "/src/libbpf/include/uapi/linux/fcntl.h"
#include <sys/stat.h>
#include "/src/libbpf/include/linux/types.h"

static int create_dummy_file(const char *filename) {
    int fd = open(filename, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        return -1;
    }
    write(fd, "dummy data", 10); // Write some dummy data
    return fd;
}

int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    const char *dummy_file = "./dummy_file";
    int map_fd = create_dummy_file(dummy_file);
    if (map_fd < 0) {
        return 0;
    }

    struct user_ring_buffer_opts opts;
    opts.sz = sizeof(opts);

    struct user_ring_buffer *rb = user_ring_buffer__new(map_fd, &opts);
    if (rb) {
        void *sample = user_ring_buffer__reserve(rb, Size);
        if (sample) {
            user_ring_buffer__submit(rb, sample);
        } else {
            sample = user_ring_buffer__reserve_blocking(rb, Size, 1000);
            if (sample) {
                user_ring_buffer__discard(rb, sample);
            }
        }
        user_ring_buffer__free(rb);
    }

    close(map_fd);
    unlink(dummy_file);

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
