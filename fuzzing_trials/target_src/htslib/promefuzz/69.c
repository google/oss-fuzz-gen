// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hfile_mem_get_buffer at hfile.c:881:7 in hfile.h
// hfile_set_blksize at hfile.c:213:5 in hfile.h
// hputc2 at hfile.c:388:5 in hfile.h
// hclearerr at hfile.h:140:20 in hfile.h
// hgetc at hfile.h:163:19 in hfile.h
// hclearerr at hfile.h:140:20 in hfile.h
// hfile_mem_steal_buffer at hfile.c:893:7 in hfile.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "hfile.h"

// Define the hFILE_backend structure since it's not fully defined in the header
struct hFILE_backend {
    ssize_t (*read)(hFILE *fp, void *buffer, size_t nbytes);
    ssize_t (*write)(hFILE *fp, const void *buffer, size_t nbytes);
    off_t (*seek)(hFILE *fp, off_t offset, int whence);
    int (*flush)(hFILE *fp);
    int (*close)(hFILE *fp);
};

static ssize_t dummy_read(hFILE *fp, void *buffer, size_t nbytes) {
    return 0; // Simulate end-of-file
}

static ssize_t dummy_write(hFILE *fp, const void *buffer, size_t nbytes) {
    return nbytes; // Simulate successful write
}

static off_t dummy_seek(hFILE *fp, off_t offset, int whence) {
    return -1; // Simulate seek failure
}

static int dummy_flush(hFILE *fp) {
    return 0; // Simulate successful flush
}

static int dummy_close(hFILE *fp) {
    return 0; // Simulate successful close
}

static const struct hFILE_backend dummy_backend = {
    .read = dummy_read,
    .write = dummy_write,
    .seek = dummy_seek,
    .flush = dummy_flush,
    .close = dummy_close
};

static hFILE *create_dummy_hfile() {
    hFILE *fp = malloc(sizeof(hFILE));
    if (!fp) return NULL;

    fp->buffer = malloc(1024);
    if (!fp->buffer) {
        free(fp);
        return NULL;
    }

    fp->begin = fp->buffer;
    fp->end = fp->buffer;
    fp->limit = fp->buffer + 1024;
    fp->backend = &dummy_backend;
    fp->offset = 0;
    fp->at_eof = 0;
    fp->mobile = 0;
    fp->readonly = 0;
    fp->preserve = 0;
    fp->has_errno = 0;

    return fp;
}

static void free_dummy_hfile(hFILE *fp) {
    if (fp) {
        free(fp->buffer);
        free(fp);
    }
}

int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    hFILE *fp = create_dummy_hfile();
    if (!fp) return 0;

    int c = Data[0];

    // Test hputc2
    int result = hputc2(c, fp);
    if (result == EOF) {
        hclearerr(fp);
    }

    // Test hgetc
    int ch = hgetc(fp);
    if (ch == EOF) {
        hclearerr(fp);
    }

    // Test hfile_mem_steal_buffer
    size_t length;
    char *buffer = hfile_mem_steal_buffer(fp, &length);
    if (buffer) {
        free(buffer);
    }

    // Test hfile_mem_get_buffer
    char *get_buffer = hfile_mem_get_buffer(fp, &length);
    if (get_buffer) {
        // Do something with the buffer
    }

    // Test hfile_set_blksize
    size_t new_bufsiz = Size > 1 ? Data[1] : 1024;
    int set_blksize_result = hfile_set_blksize(fp, new_bufsiz);

    free_dummy_hfile(fp);
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

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
