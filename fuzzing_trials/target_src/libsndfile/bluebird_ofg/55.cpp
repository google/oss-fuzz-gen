#include <sys/stat.h>
#include "sndfile.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // Include for write() and close()

extern "C" int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Define a temporary file name
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor as it will be reopened by sf_open
    close(fd);

    // Open the temporary file with libsndfile
    SF_INFO sfinfo;
    memset(&sfinfo, 0, sizeof(SF_INFO));
    SNDFILE *sndfile = sf_open(tmpl, SFM_RDWR, &sfinfo);
    if (sndfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    sf_count_t frames_written = sf_write_raw(sndfile, data, (sf_count_t)size);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sf_write_raw to sf_write_int
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    const char* ret_sf_strerror_bzrvd = sf_strerror(sndfile);
    if (ret_sf_strerror_bzrvd == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!sndfile) {
    	return 0;
    }
    sf_count_t ret_sf_write_int_weuau = sf_write_int(sndfile, (const int *)&frames_written, 1);
    if (ret_sf_write_int_weuau < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
