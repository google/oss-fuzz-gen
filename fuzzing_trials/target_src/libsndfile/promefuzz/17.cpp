// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_format_check at sndfile.c:653:1 in sndfile.h
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_get_chunk_iterator at sndfile.c:3396:1 in sndfile.h
// sf_next_chunk_iterator at sndfile.c:3408:1 in sndfile.h
// sf_get_chunk_size at sndfile.c:3421:1 in sndfile.h
// sf_get_chunk_data at sndfile.c:3437:1 in sndfile.h
// sf_set_chunk at sndfile.c:3381:1 in sndfile.h
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
#include <sndfile.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(SF_INFO)) {
        return 0;
    }

    // Prepare SF_INFO structure
    SF_INFO info;
    std::memcpy(&info, Data, sizeof(SF_INFO));

    // Fuzz sf_format_check
    sf_format_check(&info);

    // Prepare SF_CHUNK_INFO structure
    SF_CHUNK_INFO chunk_info;
    std::memset(&chunk_info, 0, sizeof(SF_CHUNK_INFO));

    // Prepare a dummy file
    FILE *file = std::fopen("./dummy_file", "wb+");
    if (!file) {
        return 0;
    }
    std::fwrite(Data, 1, Size, file);
    std::fclose(file);

    // Open the dummy file with libsndfile
    SNDFILE *sndfile = sf_open("./dummy_file", SFM_READ, &info);
    if (!sndfile) {
        return 0;
    }

    // Fuzz sf_get_chunk_iterator
    SF_CHUNK_ITERATOR *iterator = sf_get_chunk_iterator(sndfile, nullptr);

    // Fuzz sf_next_chunk_iterator
    SF_CHUNK_ITERATOR *next_iterator = sf_next_chunk_iterator(iterator);

    // Fuzz sf_get_chunk_size
    sf_get_chunk_size(iterator, &chunk_info);

    // Fuzz sf_get_chunk_data
    chunk_info.data = std::malloc(chunk_info.datalen);
    if (chunk_info.data) {
        sf_get_chunk_data(iterator, &chunk_info);
        std::free(chunk_info.data);
    }

    // Fuzz sf_set_chunk
    sf_set_chunk(sndfile, &chunk_info);

    // Cleanup
    sf_close(sndfile);
    std::remove("./dummy_file");

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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    