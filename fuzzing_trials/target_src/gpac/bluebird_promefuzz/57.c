#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) {
        return 0;
    }

    write_dummy_file(Data, Size);

    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_EDIT, NULL);
    if (!isom_file) {
        return 0;
    }

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 anotherValue = *(u32 *)(Data + sizeof(u32) * 2);

    // Fuzz gf_isom_remove_track
    gf_isom_remove_track(isom_file, trackNumber);

    // Fuzz gf_isom_evte_config_new
    u32 outDescriptionIndex;
    gf_isom_evte_config_new(isom_file, trackNumber, &outDescriptionIndex);

    // Fuzz gf_isom_set_visual_info
    gf_isom_set_visual_info(isom_file, trackNumber, sampleDescriptionIndex, anotherValue, anotherValue);

    // Fuzz gf_isom_truehd_config_get

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_set_visual_info to gf_isom_set_root_od_url
    // Ensure dataflow is valid (i.e., non-null)
    if (!isom_file) {
    	return 0;
    }
    GF_Err ret_gf_isom_set_root_od_url_jxdub = gf_isom_set_root_od_url(isom_file, (const char *)"r");
    // End mutation: Producer.APPEND_MUTATOR
    
    u32 format_info, peak_data_rate;
    gf_isom_truehd_config_get(isom_file, trackNumber, sampleDescriptionIndex, &format_info, &peak_data_rate);

    // Fuzz gf_isom_set_brand_info
    gf_isom_set_brand_info(isom_file, anotherValue, anotherValue);

    // Fuzz gf_isom_purge_track_reference

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_set_brand_info to gf_isom_new_xml_subtitle_description
    // Ensure dataflow is valid (i.e., non-null)
    if (!isom_file) {
    	return 0;
    }
    u32 ret_gf_isom_guess_specification_smisj = gf_isom_guess_specification(isom_file);
    // Ensure dataflow is valid (i.e., non-null)
    if (!isom_file) {
    	return 0;
    }
    u32 ret_gf_isom_get_next_moof_number_vqjcm = gf_isom_get_next_moof_number(isom_file);
    // Ensure dataflow is valid (i.e., non-null)
    if (!isom_file) {
    	return 0;
    }
    GF_Err ret_gf_isom_new_xml_subtitle_description_lbbkk = gf_isom_new_xml_subtitle_description(isom_file, ret_gf_isom_guess_specification_smisj, NULL, (const char *)"r", NULL, &ret_gf_isom_get_next_moof_number_vqjcm);
    // End mutation: Producer.APPEND_MUTATOR
    
    gf_isom_purge_track_reference(isom_file, trackNumber);

    gf_isom_close(isom_file);
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
