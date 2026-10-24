#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gpac/include/gpac/isomedia.h"

static GF_ISOFile* open_dummy_iso_file() {
    // Use a temporary directory for the gf_isom_open function
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, "/tmp");
}

static void close_dummy_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    // Prepare dummy ISO file
    GF_ISOFile *iso_file = open_dummy_iso_file();
    if (!iso_file) return 0;

    // Prepare dummy file for trace
    FILE *trace_file = fopen("./dummy_file", "w+");
    if (!trace_file) {
        close_dummy_iso_file(iso_file);
        return 0;
    }

    // Extract parameters from input data
    u32 trackNumber = Data[0];
    u32 sampleNumber = Data[1];
    u32 sampleDescriptionIndex = Data[2];
    u32 average_bitrate = Data[3];
    u32 max_bitrate = (Size > 4) ? Data[4] : 0;
    u32 decode_buffer_size = (Size > 5) ? Data[5] : 0;

    // Prepare for gf_isom_get_sample_references
    u32 refID = 0;
    u32 nb_refs = 0;
    const u32 *refs = NULL;

    // Fuzz gf_isom_remove_track
    gf_isom_remove_track(iso_file, trackNumber);

    // Fuzz gf_isom_dump_hint_sample
    gf_isom_dump_hint_sample(iso_file, trackNumber, sampleNumber, trace_file);

    // Fuzz gf_isom_update_bitrate
    gf_isom_update_bitrate(iso_file, trackNumber, sampleDescriptionIndex, average_bitrate, max_bitrate, decode_buffer_size);

    // Fuzz gf_isom_dump_ismacryp_protection
    gf_isom_dump_ismacryp_protection(iso_file, trackNumber, trace_file);

    // Fuzz gf_isom_get_sample_references
    gf_isom_get_sample_references(iso_file, trackNumber, sampleNumber, &refID, &nb_refs, &refs);

    // Fuzz gf_isom_dump_ismacryp_sample
    gf_isom_dump_ismacryp_sample(iso_file, trackNumber, sampleNumber, trace_file);

    // Cleanup
    fclose(trace_file);
    close_dummy_iso_file(iso_file);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
