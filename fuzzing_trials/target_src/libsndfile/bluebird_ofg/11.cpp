#include <sys/stat.h>
#include "sndfile.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {
    int sf_set_chunk(SNDFILE *, const SF_CHUNK_INFO *);
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate a sound file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) == -1) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor, we will reopen it with sf_open
    close(fd);

    // Open the temporary file with libsndfile
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    SNDFILE *sndfile = sf_open(tmpl, SFM_RDWR, &sfinfo);
    if (sndfile == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Prepare a SF_CHUNK_INFO structure

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sf_open to sf_get_chunk_iterator using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    SF_CHUNK_ITERATOR* ret_sf_get_chunk_iterator_bwjde = sf_get_chunk_iterator(sndfile, NULL);
    if (ret_sf_get_chunk_iterator_bwjde == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sf_get_chunk_iterator to sf_next_chunk_iterator using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_sf_get_chunk_iterator_bwjde) {
    	return 0;
    }
    SF_CHUNK_ITERATOR* ret_sf_next_chunk_iterator_keywq = sf_next_chunk_iterator(ret_sf_get_chunk_iterator_bwjde);
    if (ret_sf_next_chunk_iterator_keywq == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    SF_CHUNK_INFO chunk_info;
    memset(chunk_info.id, 0, sizeof(chunk_info.id)); // Initialize the id array
    chunk_info.datalen = size;
    chunk_info.data = (void *)data;

    // Call the function-under-test
    sf_set_chunk(sndfile, &chunk_info);

    // Clean up
    sf_close(sndfile);
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
