#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> // For mkstemp, write, close, and remove
#include <netcdf.h> // Assuming this is the correct header for nc_open_memio
#include <netcdf_mem.h> // For NC_memio and nc_open_memio

int LLVMFuzzerTestOneInput_197(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for meaningful testing
    if (size < 4) {
        return 0;
    }

    // Prepare the parameters for nc_open_memio
    char path[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(path);
    if (fd == -1) {
        return 0;
    }
    write(fd, data, size);
    close(fd);

    int mode = NC_NOWRITE; // Example mode, adjust as necessary

    NC_memio memio;
    memset(&memio, 0, sizeof(NC_memio));
    memio.size = size;
    memio.memory = (void *)data;

    int ncid;
    
    // Call the function-under-test
    nc_open_memio(path, mode, &memio, &ncid);

    // Clean up the temporary file
    remove(path);

    return 0;
}