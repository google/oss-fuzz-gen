#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libsndfile/include/sndfile.h"
}

extern "C" int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Open a virtual file from the data to create a valid SNDFILE object
    SF_VIRTUAL_IO vio;
    SNDFILE *sndfile;
    SF_INFO sfinfo;
    
    // Initialize the SF_VIRTUAL_IO structure
    vio.get_filelen = nullptr;
    vio.seek = nullptr;
    vio.read = nullptr;
    vio.write = nullptr;
    vio.tell = nullptr;

    // Open the virtual file
    sndfile = sf_open_virtual(&vio, SFM_READ, &sfinfo, nullptr);
    if (sndfile == nullptr) {
        return 0;
    }

    // Initialize a SF_CHUNK_ITERATOR object
    SF_CHUNK_ITERATOR* iterator = sf_get_chunk_iterator(sndfile, nullptr);
    if (iterator == nullptr) {
        sf_close(sndfile);
        return 0;
    }

    // Fuzz the sf_next_chunk_iterator function
    SF_CHUNK_ITERATOR* result = sf_next_chunk_iterator(iterator);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result != nullptr) {
        // Do something with the result, like printing or logging
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
