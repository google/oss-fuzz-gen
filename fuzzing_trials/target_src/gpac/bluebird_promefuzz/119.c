#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

#define DUMMY_FILE "./dummy_file"

static GF_ISOFile* create_dummy_isofile() {
    // Since GF_ISOFile is an incomplete type, we cannot allocate it directly
    // Assuming a function exists to create an empty ISOFile
    GF_ISOFile *file = gf_isom_open(DUMMY_FILE, GF_ISOM_OPEN_WRITE, NULL);
    return file;
}

static void cleanup_isofile(GF_ISOFile *file) {
    if (file) gf_isom_close(file);
}

int LLVMFuzzerTestOneInput_119(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    // Fuzzing gf_isom_setup_track_fragment_template
    u32 track_id = Data[0];
    u8 *boxes = (u8 *)Data;
    u32 boxes_size = (Size > 1) ? Size - 1 : 0;
    u8 force_traf_flags = Data[0] % 2;
    gf_isom_setup_track_fragment_template(isom_file, track_id, boxes, boxes_size, force_traf_flags);

    // Fuzzing gf_isom_set_track_stsd_templates
    u32 track_number = Data[0];
    u8 *stsd_data = (u8 *)Data;
    u32 stsd_data_size = (Size > 1) ? Size - 1 : 0;
    gf_isom_set_track_stsd_templates(isom_file, track_number, stsd_data, stsd_data_size);

    // Fuzzing gf_isom_append_sample_data
    u32 append_track_number = Data[0];
    u8 *append_data = (u8 *)Data;
    u32 append_data_size = (Size > 1) ? Size - 1 : 0;
    gf_isom_append_sample_data(isom_file, append_track_number, append_data, append_data_size);

    // Fuzzing gf_isom_cenc_get_sample_aux_info
    u32 sample_number = Data[0];
    u32 sample_desc_index = Data[0];
    u32 container_type = Data[0];
    u8 *out_buffer = NULL;
    u32 out_size = 0;
    gf_isom_cenc_get_sample_aux_info(isom_file, track_number, sample_number, sample_desc_index, &container_type, &out_buffer, &out_size);
    if (out_buffer) free(out_buffer);

    // Fuzzing gf_isom_fragment_append_data
    u8 *fragment_data = (u8 *)Data;
    u32 fragment_data_size = (Size > 1) ? Size - 1 : 0;
    u8 padding_bits = Data[0];
    gf_isom_fragment_append_data(isom_file, track_id, fragment_data, fragment_data_size, padding_bits);

    // Fuzzing gf_isom_fragment_set_sample_aux_info
    u32 sample_number_in_frag = Data[0];
    u32 aux_type = Data[0] + 1; // ensuring non-zero
    u32 aux_info = Data[0];
    u8 *aux_data = (u8 *)Data;
    u32 aux_size = (Size > 1) ? Size - 1 : 0;
    gf_isom_fragment_set_sample_aux_info(isom_file, track_id, sample_number_in_frag, aux_type, aux_info, aux_data, aux_size);

    cleanup_isofile(isom_file);
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

    LLVMFuzzerTestOneInput_119(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
