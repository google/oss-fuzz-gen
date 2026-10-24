// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hflush at hfile.c:377:5 in hfile.h
// hclearerr at hfile.h:140:20 in hfile.h
// hputc at hfile.h:250:19 in hfile.h
// hputc2 at hfile.c:388:5 in hfile.h
// hgetc at hfile.h:163:19 in hfile.h
// hgetc2 at hfile.c:236:5 in hfile.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hfile.h"

// Define the hFILE_backend structure as it is not fully defined in the header
struct hFILE_backend {
    ssize_t (*read)(hFILE *fp, void *buffer, size_t nbytes);
    ssize_t (*write)(hFILE *fp, const void *buffer, size_t nbytes);
    off_t (*seek)(hFILE *fp, off_t offset, int whence);
    int (*flush)(hFILE *fp);
    int (*close)(hFILE *fp);
};

// Dummy backend functions for testing
static ssize_t dummy_read(hFILE *fp, void *buffer, size_t nbytes) {
    return 0; // Simulate end-of-file
}

static ssize_t dummy_write(hFILE *fp, const void *buffer, size_t nbytes) {
    return nbytes; // Simulate successful write
}

static off_t dummy_seek(hFILE *fp, off_t offset, int whence) {
    return offset; // Simulate successful seek
}

static int dummy_flush(hFILE *fp) {
    return 0; // Simulate successful flush
}

static int dummy_close(hFILE *fp) {
    return 0; // Simulate successful close
}

// Dummy backend for testing
static const struct hFILE_backend dummy_backend = {
    .read = dummy_read,
    .write = dummy_write,
    .seek = dummy_seek,
    .flush = dummy_flush,
    .close = dummy_close
};

// Initialize a dummy hFILE structure
static hFILE *create_dummy_hfile() {
    hFILE *file = (hFILE *)malloc(sizeof(hFILE));
    if (!file) return NULL;

    file->buffer = (char *)malloc(1024); // Allocate a buffer
    file->begin = file->buffer;
    file->end = file->buffer + 1024;
    file->limit = file->buffer + 1024;
    file->backend = &dummy_backend;
    file->offset = 0;
    file->at_eof = 0;
    file->mobile = 0;
    file->readonly = 0;
    file->preserve = 0;
    file->has_errno = 0;

    return file;
}

static void destroy_dummy_hfile(hFILE *file) {
    if (file) {
        free(file->buffer);
        free(file);
    }
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Need at least one byte for a character

    hFILE *file = create_dummy_hfile();
    if (!file) return 0;

    // Use the first byte as a character to write
    int c = Data[0];

    // Test hputc
    hputc(c, file);

    // Test hputc2
    hputc2(c, file);

    // Test hgetc
    hgetc(file);

    // Test hgetc2
    hgetc2(file);

    // Test hflush
    hflush(file);

    // Test hclearerr
    hclearerr(file);

    destroy_dummy_hfile(file);
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
