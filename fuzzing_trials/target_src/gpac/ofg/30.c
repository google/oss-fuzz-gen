#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    GF_ISOFile *file = NULL;
    Bool root_meta = 1; // True
    u32 track_num = 1;
    u32 item_id = 1;
    u8 *out_data = NULL;
    u32 out_size = 0;
    u32 out_alloc_size = 0;
    const char *out_mime = NULL;
    Bool use_annex_b = 0; // False

    // Create a temporary file to simulate an ISO file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Open the temporary file as an ISO file
    file = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);
    if (!file) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    gf_isom_extract_meta_item_mem(file, root_meta, track_num, item_id, &out_data, &out_size, &out_alloc_size, &out_mime, use_annex_b);

    // Clean up
    if (out_data) {
        free(out_data);
    }
    gf_isom_close(file);
    close(fd);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
