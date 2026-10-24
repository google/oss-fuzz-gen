// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hfile_set_blksize at hfile.c:213:5 in hfile.h
// hputc2 at hfile.c:388:5 in hfile.h
// hfile_mem_steal_buffer at hfile.c:893:7 in hfile.h
// hgetc at hfile.h:163:19 in hfile.h
// hclearerr at hfile.h:140:20 in hfile.h
// hfile_mem_get_buffer at hfile.c:881:7 in hfile.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "hfile.h"

// Define the hFILE_backend structure because it's not fully defined in the header
struct hFILE_backend {
    ssize_t (*read)(hFILE *fp, void *buffer, size_t nbytes);
    ssize_t (*write)(hFILE *fp, const void *buffer, size_t nbytes);
    off_t (*seek)(hFILE *fp, off_t offset, int whence);
    int (*flush)(hFILE *fp);
    int (*close)(hFILE *fp);
};

// Dummy backend functions
static ssize_t dummy_read(hFILE *fp, void *buffer, size_t nbytes) {
    return 0;  // Simulate no data read
}

static ssize_t dummy_write(hFILE *fp, const void *buffer, size_t nbytes) {
    return nbytes;  // Simulate successful write
}

static off_t dummy_seek(hFILE *fp, off_t offset, int whence) {
    return 0;  // Simulate seek to start
}

static int dummy_flush(hFILE *fp) {
    return 0;  // Simulate successful flush
}

static int dummy_close(hFILE *fp) {
    return 0;  // Simulate successful close
}

static const struct hFILE_backend dummy_backend = {
    .read = dummy_read,
    .write = dummy_write,
    .seek = dummy_seek,
    .flush = dummy_flush,
    .close = dummy_close
};

static hFILE *create_dummy_hfile() {
    // Create a dummy hFILE with minimal initialization for testing
    hFILE *file = (hFILE *)malloc(sizeof(hFILE));
    if (!file) return NULL;

    file->buffer = (char *)malloc(1024);
    if (!file->buffer) {
        free(file);
        return NULL;
    }
    file->begin = file->buffer;
    file->end = file->buffer;
    file->limit = file->buffer + 1024;
    file->offset = 0;
    file->at_eof = 0;
    file->mobile = 0;
    file->readonly = 0;
    file->preserve = 0;
    file->has_errno = 0;

    file->backend = &dummy_backend;

    return file;
}

static void cleanup_dummy_hfile(hFILE *file) {
    if (!file) return;
    free(file->buffer);
    free(file);
}

int LLVMFuzzerTestOneInput_73(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hFILE *file = create_dummy_hfile();
    if (!file) return 0;

    // Fuzz hputc2
    int c = Data[0];
    hputc2(c, file);

    // Fuzz hfile_mem_steal_buffer
    size_t length;
    char *buffer = hfile_mem_steal_buffer(file, &length);
    if (buffer) free(buffer);

    // Fuzz hgetc
    int ch = hgetc(file);

    // Fuzz hclearerr
    hclearerr(file);

    // Fuzz hfile_mem_get_buffer
    char *buf = hfile_mem_get_buffer(file, &length);

    // Fuzz hfile_set_blksize
    if (Size > 1) {
        size_t new_size = Data[1];
        hfile_set_blksize(file, new_size);
    }

    cleanup_dummy_hfile(file);
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

    LLVMFuzzerTestOneInput_73(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
