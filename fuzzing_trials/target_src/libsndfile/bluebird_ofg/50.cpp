#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // Include for close()
#include <string.h> // Include for strncpy()

extern "C" {
    #include "sndfile.h"
}

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        return 0;
    }
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the temporary file with libsndfile
    SF_INFO sfinfo;
    SNDFILE *sndfile = sf_open(tmpl, SFM_READ, &sfinfo);
    if (sndfile == NULL) {
        remove(tmpl);
        return 0;
    }

    // Initialize a SF_CHUNK_INFO structure
    SF_CHUNK_INFO chunk_info;
    strncpy(chunk_info.id, "data", sizeof(chunk_info.id)); // Set to a valid chunk ID
    chunk_info.datalen = 0; // Set to 0 or any valid data length
    chunk_info.data = NULL; // Set to NULL or any valid data pointer

    // Call the function-under-test
    SF_CHUNK_ITERATOR *iterator = sf_get_chunk_iterator(sndfile, &chunk_info);

    // Clean up
    if (iterator != NULL) {
        sf_next_chunk_iterator(iterator); // Correct function to iterate or close
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_next_chunk_iterator to sf_write_raw
        // Ensure dataflow is valid (i.e., non-null)
        if (!sndfile) {
        	return 0;
        }
        int ret_sf_current_byterate_xynhn = sf_current_byterate(sndfile);
        if (ret_sf_current_byterate_xynhn < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!sndfile) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!iterator) {
        	return 0;
        }
        sf_count_t ret_sf_write_raw_utmrv = sf_write_raw(sndfile, (const void *)iterator, 0);
        if (ret_sf_write_raw_utmrv < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_write_raw to sf_writef_int
        // Ensure dataflow is valid (i.e., non-null)
        if (!sndfile) {
        	return 0;
        }
        int ret_sf_perror_lmovg = sf_perror(sndfile);
        if (ret_sf_perror_lmovg < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!sndfile) {
        	return 0;
        }
        sf_count_t ret_sf_writef_int_lawhb = sf_writef_int(sndfile, (const int *)&ret_sf_write_raw_utmrv, 64);
        if (ret_sf_writef_int_lawhb < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
}
    sf_close(sndfile);
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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
