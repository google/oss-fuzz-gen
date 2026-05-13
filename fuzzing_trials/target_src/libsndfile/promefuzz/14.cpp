// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_format_check at sndfile.c:653:1 in sndfile.h
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_set_chunk at sndfile.c:3381:1 in sndfile.h
// sf_get_chunk_iterator at sndfile.c:3396:1 in sndfile.h
// sf_next_chunk_iterator at sndfile.c:3408:1 in sndfile.h
// sf_get_chunk_size at sndfile.c:3421:1 in sndfile.h
// sf_get_chunk_data at sndfile.c:3437:1 in sndfile.h
// sf_next_chunk_iterator at sndfile.c:3408:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <sndfile.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    SF_INFO sfInfo;
    memcpy(&sfInfo, Data, sizeof(SF_INFO));

    // 1. Test sf_format_check
    int formatCheckResult = sf_format_check(&sfInfo);

    // Prepare a dummy sound file
    const char *dummyFileName = "./dummy_file";
    SF_CHUNK_INFO chunkInfo;
    memset(&chunkInfo, 0, sizeof(SF_CHUNK_INFO));

    // 2. Test sf_set_chunk
    SNDFILE *sndfile = sf_open(dummyFileName, SFM_RDWR, &sfInfo);
    if (sndfile) {
        sf_set_chunk(sndfile, &chunkInfo);

        // 3. Test sf_get_chunk_iterator
        SF_CHUNK_ITERATOR *chunkIterator = sf_get_chunk_iterator(sndfile, nullptr);

        // 4. Test sf_next_chunk_iterator
        if (chunkIterator) {
            SF_CHUNK_ITERATOR *nextIterator = sf_next_chunk_iterator(chunkIterator);

            // 5. Test sf_get_chunk_size
            sf_get_chunk_size(nextIterator, &chunkInfo);

            // 6. Test sf_get_chunk_data
            sf_get_chunk_data(nextIterator, &chunkInfo);

            // Clean up iterators
            sf_next_chunk_iterator(nextIterator);
        }

        sf_close(sndfile);
    }

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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    