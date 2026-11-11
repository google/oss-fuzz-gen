#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

extern int nc_put_varm_text(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const ptrdiff_t *imap, const char *op);

int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + 2) {
        return 0;
    }

    int ncid = data[0];
    int varid = data[1];

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    ptrdiff_t imap[1];

    memcpy(start, data + 2, sizeof(size_t));
    memcpy(count, data + 2 + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + 2 + sizeof(size_t) * 2, sizeof(ptrdiff_t));
    memcpy(imap, data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t), sizeof(ptrdiff_t));

    const char *op = (const char *)(data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);

    // Ensure the string is null-terminated
    char op_buffer[256];
    size_t op_len = size - (2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);
    if (op_len >= sizeof(op_buffer)) {
        op_len = sizeof(op_buffer) - 1;
    }
    memcpy(op_buffer, op, op_len);
    op_buffer[op_len] = '\0';

    nc_put_varm_text(ncid, varid, start, count, stride, imap, op_buffer);

    return 0;
}