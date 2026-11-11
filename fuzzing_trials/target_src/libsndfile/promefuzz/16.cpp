// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_format_check at sndfile.c:653:1 in sndfile.h
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_get_chunk_iterator at sndfile.c:3396:1 in sndfile.h
// sf_get_chunk_size at sndfile.c:3421:1 in sndfile.h
// sf_get_chunk_data at sndfile.c:3437:1 in sndfile.h
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
#include <cstring>
#include <fstream>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    std::ofstream file("./dummy_file", std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(Data), Size);
        file.close();
    }
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    // Write the input data to a dummy file
    writeDummyFile(Data, Size);

    // Initialize SF_INFO structure
    SF_INFO sf_info = {};
    sf_info.samplerate = 44100;
    sf_info.frames = 1000;

    // Test sf_format_check
    sf_format_check(&sf_info);

    // Open the dummy file
    SNDFILE *sndfile = sf_open("./dummy_file", SFM_READ, &sf_info);
    if (!sndfile) {
        return 0;
    }

    // Initialize SF_CHUNK_INFO structure
    SF_CHUNK_INFO chunk_info = {};
    chunk_info.id_size = 4;
    std::memcpy(chunk_info.id, "fmt ", 4);

    // Test sf_get_chunk_iterator
    SF_CHUNK_ITERATOR *iterator = sf_get_chunk_iterator(sndfile, &chunk_info);
    if (iterator) {
        // Test sf_get_chunk_size
        sf_get_chunk_size(iterator, &chunk_info);

        // Test sf_get_chunk_data
        chunk_info.data = new char[chunk_info.datalen];
        sf_get_chunk_data(iterator, &chunk_info);
        delete[] static_cast<char*>(chunk_info.data);

        // Test sf_next_chunk_iterator
        SF_CHUNK_ITERATOR *next_iterator = sf_next_chunk_iterator(iterator);
        if (next_iterator) {
            sf_get_chunk_size(next_iterator, &chunk_info);
            sf_get_chunk_data(next_iterator, &chunk_info);
        }
    }

    // Test sf_set_chunk
    sf_set_chunk(sndfile, &chunk_info);

    // Close the file
    sf_close(sndfile);

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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    