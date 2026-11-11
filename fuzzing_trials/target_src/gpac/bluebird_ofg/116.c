#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_get_meta_type to gf_isom_get_chapter
    u32 ret_gf_isom_get_copyright_count_uqfgg = gf_isom_get_copyright_count(NULL);
    u32 ret_gf_isom_get_copyright_count_iqoda = gf_isom_get_copyright_count(NULL);
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    u64 ret_gf_isom_estimate_size_mxavv = gf_isom_estimate_size(file);
    const char *xwqrrcwx[1024] = {"piojl", NULL};
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    GF_Err ret_gf_isom_get_chapter_tguuu = gf_isom_get_chapter(file, ret_gf_isom_get_copyright_count_uqfgg, ret_gf_isom_get_copyright_count_iqoda, &ret_gf_isom_estimate_size_mxavv, xwqrrcwx);
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_get_chapter to gf_isom_new_mpeg4_description
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    u32 ret_gf_isom_get_next_moof_number_bcisk = gf_isom_get_next_moof_number(file);
    u32 ret_gf_isom_probe_file_lpied = gf_isom_probe_file((const char *)"r");
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    GF_Err ret_gf_isom_new_mpeg4_description_qgxev = gf_isom_new_mpeg4_description(file, ret_gf_isom_get_next_moof_number_bcisk, NULL, NULL, NULL, &ret_gf_isom_probe_file_lpied);
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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
