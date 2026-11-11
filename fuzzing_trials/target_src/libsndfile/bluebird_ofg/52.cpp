#include <sys/stat.h>
#include <string.h>
#include "sndfile.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for at least one float
    if (size < sizeof(float)) {
        return 0;
    }

    // Create a temporary file to use with SNDFILE
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Set up SF_INFO structure
    SF_INFO sfinfo;
    sfinfo.frames = 0;
    sfinfo.samplerate = 44100; // Common sample rate
    sfinfo.channels = 1; // Mono
    sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_PCM_16; // WAV format, PCM 16

    // Open the temporary file as a SNDFILE
    SNDFILE *sndfile = sf_open_fd(fd, SFM_WRITE, &sfinfo, 1);
    if (sndfile == NULL) {
        close(fd);
        return 0;
    }

    // Cast data to float pointer
    const float *float_data = reinterpret_cast<const float *>(data);
    sf_count_t float_count = size / sizeof(float);

    // Call the function-under-test
    sf_count_t written_count = sf_write_float(sndfile, float_data, float_count);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_write_float to sf_readf_short
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    sf_write_sync(sndfile);
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function sf_readf_short with sf_read_short
    sf_count_t ret_sf_readf_short_fxlom = sf_read_short(sndfile, (short *)&written_count, written_count);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    if (ret_sf_readf_short_fxlom < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_readf_short to sf_readf_double
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    int ret_sf_perror_mgbwj = sf_perror(sndfile);
    if (ret_sf_perror_mgbwj < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    sf_count_t ret_sf_readf_double_ndtkc = sf_readf_double(sndfile, (double *)&ret_sf_readf_short_fxlom, 0);
    if (ret_sf_readf_double_ndtkc < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_readf_double to sf_read_float
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    int ret_sf_perror_iuxrh = sf_perror(sndfile);
    if (ret_sf_perror_iuxrh < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    sf_count_t ret_sf_read_float_qvubs = sf_read_float(sndfile, (float *)&ret_sf_readf_double_ndtkc, size);
    if (ret_sf_read_float_qvubs < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    sf_close(sndfile);
    close(fd);
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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
