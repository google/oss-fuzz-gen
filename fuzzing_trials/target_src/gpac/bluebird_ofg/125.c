#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_open to gf_isom_new_mj2k_description
    u32 ret_gf_isom_get_supported_box_type_gsxsx = gf_isom_get_supported_box_type(0);
    u32 ret_gf_isom_segment_get_fragment_count_etebf = gf_isom_segment_get_fragment_count(NULL);
    u8 ret_gf_isom_get_mode_rgppq = gf_isom_get_mode(NULL);
    u32 ret_gf_isom_get_next_alternate_group_id_hxswz = gf_isom_get_next_alternate_group_id(NULL);
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    GF_Err ret_gf_isom_new_mj2k_description_hiazo = gf_isom_new_mj2k_description(file, ret_gf_isom_get_supported_box_type_gsxsx, (const char *)"r", (const char *)"r", &ret_gf_isom_segment_get_fragment_count_etebf, &ret_gf_isom_get_mode_rgppq, ret_gf_isom_get_next_alternate_group_id_hxswz);
    // End mutation: Producer.APPEND_MUTATOR
    
    gf_isom_get_meta_type(file, root_meta, track_num);

    // Close the ISO file and clean up
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

    LLVMFuzzerTestOneInput_125(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
