// This fuzz driver is generated for library libsndfile, aiming to fuzz the following functions:
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_writef_double at sndfile.c:2632:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_write_double at sndfile.c:2575:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_open at sndfile.c:348:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_read_double at sndfile.c:2072:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
// sf_readf_double at sndfile.c:2127:1 in sndfile.h
// sf_close at sndfile.c:517:1 in sndfile.h
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) {
        return 0; // Not enough data to form even one double element
    }

    // Create a dummy file
    const char *filename = "./dummy_file";
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    sfinfo.channels = 2; // Assume stereo for simplicity
    sfinfo.samplerate = 44100;
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;

    // Open the file for writing
    SNDFILE *sndfile = sf_open(filename, SFM_WRITE, &sfinfo);
    if (!sndfile) {
        return 0; // Unable to open file for writing
    }

    size_t num_doubles = Size / sizeof(double);
    double *double_data = reinterpret_cast<double *>(const_cast<uint8_t *>(Data));

    // Test sf_writef_double
    sf_count_t frames_written = sf_writef_double(sndfile, double_data, num_doubles / sfinfo.channels);
    if (frames_written < 0) {
        // Error handling
        sf_close(sndfile);
        return 0;
    }

    // Test sf_write_double
    sf_count_t items_written = sf_write_double(sndfile, double_data, num_doubles);
    if (items_written < 0) {
        // Error handling
        sf_close(sndfile);
        return 0;
    }

    // Close and reopen the file for reading
    sf_close(sndfile);
    sndfile = sf_open(filename, SFM_READ, &sfinfo);
    if (!sndfile) {
        return 0; // Unable to open file for reading
    }

    // Prepare a buffer for reading
    double *read_buffer = static_cast<double *>(malloc(Size));
    if (!read_buffer) {
        sf_close(sndfile);
        return 0; // Memory allocation failed
    }

    // Test sf_read_double
    sf_count_t items_read = sf_read_double(sndfile, read_buffer, num_doubles);
    if (items_read < 0) {
        // Error handling
        free(read_buffer);
        sf_close(sndfile);
        return 0;
    }

    // Test sf_readf_double
    sf_count_t frames_read = sf_readf_double(sndfile, read_buffer, num_doubles / sfinfo.channels);
    if (frames_read < 0) {
        // Error handling
        free(read_buffer);
        sf_close(sndfile);
        return 0;
    }

    // Clean up
    free(read_buffer);
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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    