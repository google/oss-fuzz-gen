// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// sam_hdr_parse at sam.c:1815:12 in sam.h
// sam_hdr_destroy at sam.c:117:6 in sam.h
// sam_hdr_find_tag_id at header.c:2282:5 in sam.h
// sam_hdr_find_line_pos at header.c:1749:5 in sam.h
// sam_hdr_count_lines at header.c:2142:5 in sam.h
// sam_hdr_remove_tag_id at header.c:2345:5 in sam.h
// sam_hdr_find_tag_pos at header.c:2314:5 in sam.h
// sam_hdr_find_line_id at header.c:1725:5 in sam.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sam.h>

static sam_hdr_t* create_dummy_sam_hdr() {
    sam_hdr_t* hdr = (sam_hdr_t*)calloc(1, sizeof(sam_hdr_t));
    if (!hdr) return NULL;

    hdr->hrecs = sam_hdr_parse(0, NULL); // Use sam_hdr_parse to initialize hrecs
    if (!hdr->hrecs) {
        free(hdr);
        return NULL;
    }

    return hdr;
}

static void destroy_dummy_sam_hdr(sam_hdr_t* hdr) {
    if (!hdr) return;
    if (hdr->hrecs) {
        sam_hdr_destroy(hdr->hrecs);
    }
    free(hdr);
}

int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sam_hdr_t* hdr = create_dummy_sam_hdr();
    if (!hdr) return 0;

    kstring_t ks = {0, 0, NULL};
    const char* type = "SQ";
    const char* ID_key = "SN";
    const char* ID_value = "ref1";
    const char* key = "LN";

    // Fuzz sam_hdr_find_tag_id
    sam_hdr_find_tag_id(hdr, type, ID_key, ID_value, key, &ks);

    // Fuzz sam_hdr_find_line_pos
    int pos = Data[0] % 10; // use first byte for position
    sam_hdr_find_line_pos(hdr, type, pos, &ks);

    // Fuzz sam_hdr_count_lines
    sam_hdr_count_lines(hdr, type);

    // Fuzz sam_hdr_remove_tag_id
    sam_hdr_remove_tag_id(hdr, type, ID_key, ID_value, key);

    // Fuzz sam_hdr_find_tag_pos
    sam_hdr_find_tag_pos(hdr, type, pos, key, &ks);

    // Fuzz sam_hdr_find_line_id
    sam_hdr_find_line_id(hdr, type, ID_key, ID_value, &ks);

    free(ks.s);
    destroy_dummy_sam_hdr(hdr);

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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
