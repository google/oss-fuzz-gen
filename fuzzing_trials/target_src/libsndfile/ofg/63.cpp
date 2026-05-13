#include <sndfile.h>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the test
    if (size < sizeof(SF_VIRTUAL_IO) + sizeof(SF_INFO)) {
        return 0;
    }

    // Initialize SF_VIRTUAL_IO with dummy functions
    SF_VIRTUAL_IO virtual_io;
    virtual_io.get_filelen = [](void *user_data) -> sf_count_t { return 0; };
    virtual_io.seek = [](sf_count_t offset, int whence, void *user_data) -> sf_count_t { return 0; };
    virtual_io.read = [](void *ptr, sf_count_t count, void *user_data) -> sf_count_t { return 0; };
    virtual_io.write = [](const void *ptr, sf_count_t count, void *user_data) -> sf_count_t { return 0; };
    virtual_io.tell = [](void *user_data) -> sf_count_t { return 0; };

    // Initialize SF_INFO with some default values
    SF_INFO sfinfo;
    sfinfo.frames = 0;
    sfinfo.samplerate = 44100;
    sfinfo.channels = 2;
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;
    sfinfo.sections = 1;
    sfinfo.seekable = 1;

    // Use the data as a user_data pointer
    void *user_data = (void *)data;

    // Open the virtual sound file
    SNDFILE *sndfile = sf_open_virtual(&virtual_io, SFM_READ, &sfinfo, user_data);

    // If the file was opened successfully, close it
    if (sndfile != nullptr) {
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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
