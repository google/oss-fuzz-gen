#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Allocate memory for GF_ISOFile
    GF_ISOFile* isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static void cleanup_iso_file(GF_ISOFile* isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_73(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile* isom_file = create_dummy_iso_file();
    if (!isom_file) return 0;

    u32 trackNumber = Data[0];
    u8 flag1 = (Size > 1) ? Data[1] : 0;
    u8 flag2 = (Size > 2) ? Data[2] : 0;
    u8 flag3 = (Size > 3) ? Data[3] : 0;
    u8 flag4 = (Size > 4) ? Data[4] : 0;
    u8 flag5 = (Size > 5) ? Data[5] : 0;

    // Test gf_isom_rtp_packet_set_flags
    gf_isom_rtp_packet_set_flags(isom_file, trackNumber, flag1, flag2, flag3, flag4, flag5);

    // Test gf_isom_hint_blank_data
    gf_isom_hint_blank_data(isom_file, trackNumber, flag1);

    // Test gf_isom_hint_direct_data
    u8 data[14];
    u32 dataLength = (Size > 14) ? 14 : Size;
    memcpy(data, Data, dataLength);
    gf_isom_hint_direct_data(isom_file, trackNumber, data, dataLength, flag1);

    // Test gf_isom_append_sample_data
    gf_isom_append_sample_data(isom_file, trackNumber, data, dataLength);

    // Test gf_isom_cenc_get_sample_aux_info
    u32 sampleNumber = (Size > 6) ? Data[6] : 0;
    u32 sampleDescIndex = (Size > 7) ? Data[7] : 0;
    u32 container_type = 0;
    u8 *out_buffer = NULL;
    u32 outSize = 0;
    gf_isom_cenc_get_sample_aux_info(isom_file, trackNumber, sampleNumber, sampleDescIndex, &container_type, &out_buffer, &outSize);

    // Test gf_isom_add_user_data_boxes
    gf_isom_add_user_data_boxes(isom_file, trackNumber, data, dataLength);

    free(out_buffer);
    cleanup_iso_file(isom_file);
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
