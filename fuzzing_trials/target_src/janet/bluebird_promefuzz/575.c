#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "janet.h"

static void initialize_stream(JanetStream *stream) {
    memset(stream, 0, sizeof(JanetStream));
    stream->handle = -1; // Invalid handle
}

static void initialize_buffer(JanetBuffer *buffer) {
    memset(buffer, 0, sizeof(JanetBuffer));
    buffer->capacity = 1024; // Arbitrary initial capacity
    buffer->data = (uint8_t *)malloc(buffer->capacity);
}

static void cleanup_buffer(JanetBuffer *buffer) {
    free(buffer->data);
}

static void cleanup_stream(JanetStream *stream) {
    if (stream->handle != -1) {
        close(stream->handle);
        stream->handle = -1;
    }
}

int LLVMFuzzerTestOneInput_575(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetStream) + sizeof(int32_t) + sizeof(int) + sizeof(void *)) {
        return 0;
    }

    JanetStream stream;
    initialize_stream(&stream);

    JanetBuffer buffer;
    initialize_buffer(&buffer);

    int32_t nbytes = *(int32_t *)(Data + sizeof(JanetStream));
    int flags = *(int *)(Data + sizeof(JanetStream) + sizeof(int32_t));

    // Validate nbytes to prevent excessive memory operations
    if (nbytes < 0 || nbytes > buffer.capacity) {
        nbytes = buffer.capacity;
    }

    // Fuzz janet_ev_recvfrom
    if (stream.handle != -1) {
        janet_ev_recvfrom(&stream, &buffer, nbytes, flags);
    }

    // Fuzz janet_ev_recv
    if (stream.handle != -1) {
        janet_ev_recv(&stream, &buffer, nbytes, flags);
    }

    // Fuzz janet_ev_read
    if (stream.handle != -1) {
        janet_ev_read(&stream, &buffer, nbytes);
    }

    // Fuzz janet_ev_sendto_buffer
    void *dest = (void *)(Data + sizeof(JanetStream) + sizeof(int32_t) + sizeof(int));
    if (stream.handle != -1) {
        janet_ev_sendto_buffer(&stream, &buffer, dest, flags);
    }

    // Fuzz janet_stream_close
    janet_stream_close(&stream);

    // Fuzz janet_loop
    janet_loop();

    cleanup_buffer(&buffer);
    cleanup_stream(&stream);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_575(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
