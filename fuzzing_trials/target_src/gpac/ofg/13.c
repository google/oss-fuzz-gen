#include <gpac/isomedia.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate the GF_ISOFile input
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

    // Close the file descriptor
    close(fd);

    // Open the file as a GF_ISOFile
    GF_ISOFile *file = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);
    if (!file) {
        unlink(tmpl);
        return 0;
    }

    // Initialize parameters for the function call
    Bool root_meta = GF_FALSE;
    u32 track_num = 1;
    u32 item_id = 1;
    Bool is_protected;
    u32 skip_byte_block;
    u32 crypt_byte_block;
    const u8 *key_info;
    u32 key_info_size;
    u32 aux_info_type_param;
    u8 *cenc_sai_data;
    u32 cenc_sai_data_size;
    u32 cenc_sai_alloc_size;

    // Call the function-under-test
    gf_isom_extract_meta_item_get_cenc_info(file, root_meta, track_num, item_id, &is_protected,
                                            &skip_byte_block, &crypt_byte_block, &key_info, &key_info_size,
                                            &aux_info_type_param, &cenc_sai_data, &cenc_sai_data_size, &cenc_sai_alloc_size);

    // Clean up
    gf_isom_close(file);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
