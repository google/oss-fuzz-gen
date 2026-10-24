// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// ring_buffer__poll at ringbuf.c:336:5 in libbpf.h
// ring__consume_n at ringbuf.c:406:5 in libbpf.h
// ring__consume at ringbuf.c:417:5 in libbpf.h
// ring__map_fd at ringbuf.c:401:5 in libbpf.h
// ring_buffer__epoll_fd at ringbuf.c:360:5 in libbpf.h
// ring_buffer__consume at ringbuf.c:312:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <limits.h>

struct ring_buffer {
    struct epoll_event *events;
    struct ring **rings;
    size_t page_size;
    int epoll_fd;
    int ring_cnt;
};

struct ring {
    ring_buffer_sample_fn sample_cb;
    void *ctx;
    void *data;
    unsigned long *consumer_pos;
    unsigned long *producer_pos;
    unsigned long mask;
    int map_fd;
};

static struct ring_buffer* create_dummy_ring_buffer() {
    struct ring_buffer *rb = malloc(sizeof(struct ring_buffer));
    if (!rb) return NULL;

    rb->events = malloc(sizeof(struct epoll_event) * 10);
    if (!rb->events) {
        free(rb);
        return NULL;
    }

    rb->rings = malloc(sizeof(struct ring*) * 10);
    if (!rb->rings) {
        free(rb->events);
        free(rb);
        return NULL;
    }

    for (int i = 0; i < 10; i++) {
        rb->rings[i] = malloc(sizeof(struct ring));
        if (!rb->rings[i]) {
            for (int j = 0; j < i; j++) free(rb->rings[j]);
            free(rb->rings);
            free(rb->events);
            free(rb);
            return NULL;
        }
    }

    rb->page_size = 4096;
    rb->epoll_fd = epoll_create1(0);
    rb->ring_cnt = 10;

    return rb;
}

static void destroy_dummy_ring_buffer(struct ring_buffer *rb) {
    if (!rb) return;
    for (int i = 0; i < rb->ring_cnt; i++) {
        free(rb->rings[i]);
    }
    free(rb->rings);
    free(rb->events);
    close(rb->epoll_fd);
    free(rb);
}

static struct ring* create_dummy_ring() {
    struct ring *r = malloc(sizeof(struct ring));
    if (!r) return NULL;

    r->consumer_pos = malloc(sizeof(unsigned long));
    r->producer_pos = malloc(sizeof(unsigned long));
    if (!r->consumer_pos || !r->producer_pos) {
        free(r->consumer_pos);
        free(r->producer_pos);
        free(r);
        return NULL;
    }

    r->map_fd = open("./dummy_file", O_CREAT | O_RDWR, 0666);
    if (r->map_fd < 0) {
        free(r->consumer_pos);
        free(r->producer_pos);
        free(r);
        return NULL;
    }

    r->mask = 0xFFFFFFFF;
    r->data = NULL;
    r->ctx = NULL;
    r->sample_cb = NULL;

    return r;
}

static void destroy_dummy_ring(struct ring *r) {
    if (!r) return;
    close(r->map_fd);
    free(r->consumer_pos);
    free(r->producer_pos);
    free(r);
}

int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    struct ring_buffer *rb = create_dummy_ring_buffer();
    if (!rb) return 0;

    struct ring *r = create_dummy_ring();
    if (!r) {
        destroy_dummy_ring_buffer(rb);
        return 0;
    }

    int timeout_ms = *(int*)Data;
    int ret;

    // Fuzz ring_buffer__poll
    ret = ring_buffer__poll(rb, timeout_ms);

    // Fuzz ring__consume_n
    size_t n = Size % 1024;
    ret = ring__consume_n(r, n);

    // Fuzz ring__consume
    ret = ring__consume(r);

    // Fuzz ring__map_fd
    ret = ring__map_fd(r);

    // Fuzz ring_buffer__epoll_fd
    ret = ring_buffer__epoll_fd(rb);

    // Fuzz ring_buffer__consume
    ret = ring_buffer__consume(rb);

    destroy_dummy_ring(r);
    destroy_dummy_ring_buffer(rb);

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

        LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    