#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> // For mkstemp
#include <string.h> // For memcpy
#include <unistd.h> // For close

extern "C" {
    #include "sndfile.h"

    SF_CHUNK_ITERATOR * sf_get_chunk_iterator(SNDFILE *, const SF_CHUNK_INFO *);
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    if (size < sizeof(SF_CHUNK_INFO)) {
        return 0; // Not enough data to form a valid SF_CHUNK_INFO
    }

    // Create a temporary file to simulate an audio file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
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
    if (!sndfile) {
        remove(tmpl);
        return 0;
    }

    // Initialize SF_CHUNK_INFO from the input data
    SF_CHUNK_INFO chunk_info;
    memcpy(&chunk_info, data, sizeof(SF_CHUNK_INFO));

    // Call the function-under-test
    SF_CHUNK_ITERATOR *iterator = sf_get_chunk_iterator(sndfile, &chunk_info);

    // Cleanup
    if (iterator) {
        // Assuming there is a function to free the iterator if needed
        // sf_free_chunk_iterator(iterator);
    }

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sf_get_chunk_iterator to sf_next_chunk_iterator using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!iterator) {
    	return 0;
    }
    SF_CHUNK_ITERATOR* ret_sf_next_chunk_iterator_dpazm = sf_next_chunk_iterator(iterator);
    if (ret_sf_next_chunk_iterator_dpazm == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
