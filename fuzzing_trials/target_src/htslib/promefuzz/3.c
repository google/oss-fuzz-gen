// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// sam_hdr_destroy at sam.c:117:6 in sam.h
// sam_hdr_add_line at header.c:1692:5 in sam.h
// sam_hdr_line_index at header.c:2185:5 in sam.h
// sam_hdr_name2tid at header.c:2392:5 in sam.h
// sam_hdr_remove_line_id at header.c:1783:5 in sam.h
// sam_hdr_update_line at header.c:1909:5 in sam.h
// sam_hdr_remove_except at header.c:2014:5 in sam.h
// sam_hdr_init at sam.c:108:12 in sam.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sam.h"

static sam_hdr_t *create_dummy_header() {
    sam_hdr_t *header = sam_hdr_init();
    if (!header) return NULL;

    return header;
}

static void cleanup_header(sam_hdr_t *header) {
    if (header) {
        sam_hdr_destroy(header);
    }
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    sam_hdr_t *header = create_dummy_header();
    if (!header) return 0;

    // Prepare dummy data
    const char *type = "SQ";
    const char *key = "SN";
    const char *value = "ref1";

    // Test sam_hdr_add_line
    int ret = sam_hdr_add_line(header, type, key, value, "LN", "100", NULL);
    if (ret < 0) {
        cleanup_header(header);
        return 0;
    }

    // Test sam_hdr_line_index
    int index = sam_hdr_line_index(header, type, value);
    if (index < -1) {
        cleanup_header(header);
        return 0;
    }

    // Test sam_hdr_name2tid
    int tid = sam_hdr_name2tid(header, value);
    if (tid < -1) {
        cleanup_header(header);
        return 0;
    }

    // Test sam_hdr_remove_line_id
    ret = sam_hdr_remove_line_id(header, type, key, value);
    if (ret < 0) {
        cleanup_header(header);
        return 0;
    }

    // Test sam_hdr_update_line
    ret = sam_hdr_update_line(header, type, key, value, "M5", "d41d8cd98f00b204e9800998ecf8427e", NULL);
    if (ret < 0) {
        cleanup_header(header);
        return 0;
    }

    // Test sam_hdr_remove_except
    ret = sam_hdr_remove_except(header, type, key, value);
    if (ret < 0) {
        cleanup_header(header);
        return 0;
    }

    cleanup_header(header);
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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
