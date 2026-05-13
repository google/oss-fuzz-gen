#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    GF_ISOFile *file = NULL;
    Bool root_meta = GF_FALSE;
    u32 track_num = 1;

    // Ensure the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to store the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the ISO file using the temporary file
    file = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);
    if (file == NULL) {
        // Clean up the temporary file if opening fails
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    gf_isom_get_meta_type(file, root_meta, track_num);

    // Close the ISO file and clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_get_meta_type to gf_isom_is_self_contained
    u32 ret_gf_isom_probe_file_gbnuc = gf_isom_probe_file((const char *)"w");
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_probe_file to gf_isom_get_ismacryp_info
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    Bool ret_gf_isom_is_fragmented_uqcfq = gf_isom_is_fragmented(file);
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    u32 ret_gf_isom_get_track_count_wyuzi = gf_isom_get_track_count(file);
    u32 ret_gf_isom_get_supported_box_type_fdwjw = gf_isom_get_supported_box_type(ret_gf_isom_probe_file_gbnuc);
    u32 ret_gf_isom_get_timescale_djoyi = gf_isom_get_timescale(NULL);
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    u32 ret_gf_isom_get_next_alternate_group_id_oohny = gf_isom_get_next_alternate_group_id(file);
    Bool ret_gf_isom_is_fragmented_tqths = gf_isom_is_fragmented(NULL);
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    u32 ret_gf_isom_get_next_alternate_group_id_wkqor = gf_isom_get_next_alternate_group_id(file);
    u32 ret_gf_isom_get_timescale_lvcbf = gf_isom_get_timescale(NULL);
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    GF_Err ret_gf_isom_get_ismacryp_info_lbwox = gf_isom_get_ismacryp_info(file, ret_gf_isom_get_track_count_wyuzi, ret_gf_isom_get_supported_box_type_fdwjw, &ret_gf_isom_get_timescale_djoyi, &ret_gf_isom_get_next_alternate_group_id_oohny, &ret_gf_isom_probe_file_gbnuc, NULL, (const char **)"r", &ret_gf_isom_is_fragmented_tqths, &ret_gf_isom_get_next_alternate_group_id_wkqor, &ret_gf_isom_get_timescale_lvcbf);
    // End mutation: Producer.APPEND_MUTATOR
    
    u32 ret_gf_isom_guess_specification_thcsk = gf_isom_guess_specification(file);
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    Bool ret_gf_isom_is_self_contained_hhrzy = gf_isom_is_self_contained(file, ret_gf_isom_probe_file_gbnuc, ret_gf_isom_guess_specification_thcsk);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_is_self_contained to gf_isom_find_od_id_for_track
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    u32 ret_gf_isom_get_track_count_itbku = gf_isom_get_track_count(file);
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    u32 ret_gf_isom_find_od_id_for_track_telwq = gf_isom_find_od_id_for_track(file, ret_gf_isom_get_track_count_itbku);
    // End mutation: Producer.APPEND_MUTATOR
    
    gf_isom_close(file);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
