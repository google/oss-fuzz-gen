// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_format_check at sndfile.c:653:1 in sndfile.h
// sf_get_chunk_size at sndfile.c:3421:1 in sndfile.h
// sf_next_chunk_iterator at sndfile.c:3408:1 in sndfile.h
// sf_set_chunk at sndfile.c:3381:1 in sndfile.h
// sf_get_chunk_iterator at sndfile.c:3396:1 in sndfile.h
// sf_get_chunk_data at sndfile.c:3437:1 in sndfile.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sndfile.h>
#include <cassert>
#include <cstdio>

// Define a dummy SF_CHUNK_ITERATOR structure as it's opaque in the header
struct SF_CHUNK_ITERATOR {
    uint32_t current;
    int64_t hash;
    char id[64];
    unsigned id_size;
    SNDFILE *sndfile;
};

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) return 0;

    // Create a dummy file to be used by the functions
    FILE *dummyFile = fopen("./dummy_file", "wb+");
    if (!dummyFile) return 0;

    // Prepare SF_INFO structure
    SF_INFO info;
    memcpy(&info, Data, sizeof(SF_INFO));

    // 1. Fuzz sf_format_check
    int isValidFormat = sf_format_check(&info);
    assert(isValidFormat == 0 || isValidFormat == 1);

    // Prepare SF_CHUNK_INFO structure
    SF_CHUNK_INFO chunkInfo;
    size_t id_copy_size = (Size < sizeof(chunkInfo.id)) ? Size : sizeof(chunkInfo.id);
    memcpy(chunkInfo.id, Data, id_copy_size);
    chunkInfo.id_size = Size % 64;
    chunkInfo.data = nullptr;

    // Prepare SF_CHUNK_ITERATOR structure
    SF_CHUNK_ITERATOR chunkIterator;
    chunkIterator.current = 0;
    chunkIterator.hash = 0;
    id_copy_size = (Size < sizeof(chunkIterator.id)) ? Size : sizeof(chunkIterator.id);
    memcpy(chunkIterator.id, Data, id_copy_size);
    chunkIterator.id_size = Size % 64;
    chunkIterator.sndfile = nullptr;

    // 2. Fuzz sf_get_chunk_size
    int chunkSizeResult = sf_get_chunk_size(&chunkIterator, &chunkInfo);
    assert(chunkSizeResult == SF_ERR_NO_ERROR || chunkInfo.datalen == 0);

    // 3. Fuzz sf_next_chunk_iterator
    SF_CHUNK_ITERATOR *nextIterator = sf_next_chunk_iterator(&chunkIterator);
    if (nextIterator) {
        // Use the new iterator
    }

    // 4. Fuzz sf_set_chunk
    SNDFILE *sndfile = nullptr;  // This would be opened using sf_open in a real scenario
    int setChunkResult = sf_set_chunk(sndfile, &chunkInfo);
    assert(setChunkResult == SF_ERR_NO_ERROR || setChunkResult != 0);

    // 5. Fuzz sf_get_chunk_iterator
    SF_CHUNK_ITERATOR *iterator = sf_get_chunk_iterator(sndfile, &chunkInfo);
    if (iterator) {
        // Use the iterator
    }

    // 6. Fuzz sf_get_chunk_data
    int getChunkDataResult = sf_get_chunk_data(&chunkIterator, &chunkInfo);
    assert(getChunkDataResult == SF_ERR_NO_ERROR || chunkInfo.datalen == 0);

    fclose(dummyFile);
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    