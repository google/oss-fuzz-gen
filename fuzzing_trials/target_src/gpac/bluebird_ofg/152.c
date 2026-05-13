#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> // Include for close() and write()
#include <stdio.h>  // Include for remove()
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    GF_ISOFile *file = NULL;
    Bool root_meta;
    u32 track_num;

    // Ensure the input size is sufficient for our needs
    if (size < sizeof(Bool) + sizeof(u32)) {
        return 0;
    }

    // Initialize parameters
    root_meta = (Bool)data[0]; // Use the first byte for root_meta
    track_num = *((u32 *)(data + 1)); // Use the next 4 bytes for track_num

    // Create a temporary file to simulate an ISO file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the ISO file using the temporary file path
    file = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);
    if (file == NULL) {
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    gf_isom_has_meta_xml(file, root_meta, track_num);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from gf_isom_has_meta_xml to gf_isom_is_track_fragmented
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    u32 ret_gf_isom_get_copyright_count_sxodq = gf_isom_get_copyright_count(file);
    // Ensure dataflow is valid (i.e., non-null)
    if (!file) {
    	return 0;
    }
    Bool ret_gf_isom_is_track_fragmented_vadto = gf_isom_is_track_fragmented(file, ret_gf_isom_get_copyright_count_sxodq);
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

    LLVMFuzzerTestOneInput_152(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
