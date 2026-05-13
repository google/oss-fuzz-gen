#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "netcdf.h"
#include "netcdf_mem.h"  // Include this header for NC_memio and nc_open_memio

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the test
    if (size < 1) {
        return 0;
    }

    // Create a temporary filename
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);  // Ensure the temporary file is removed
        return 0;
    }
    close(fd);

    // Prepare parameters for nc_open_memio
    int mode = NC_NOWRITE;  // Using a common mode for opening
    NC_memio memio;
    int ncid;

    // Initialize the memio structure
    memio.size = size;
    memio.memory = malloc(size);
    if (memio.memory == NULL) {
        unlink(tmpl);
        return 0;
    }
    memcpy(memio.memory, data, size);
    memio.flags = 0;  // Ensure flags are set to zero, indicating no special handling

    // Call the function-under-test
    int result = nc_open_memio(tmpl, mode, &memio, &ncid);

    // If nc_open_memio is successful, close the file and free resources
    if (result == NC_NOERR) {
        nc_close(ncid);
    }

    // Clean up
    // Remove the temporary file only after nc_open_memio to avoid double-free
    unlink(tmpl);

    // Ensure that we do not double-free the memory
    // Free the memory only if nc_open_memio was not successful, as it might manage the memory itself
    if (result != NC_NOERR && memio.memory != NULL) {
        free(memio.memory);
        memio.memory = NULL;  // Set pointer to NULL after freeing
    }

    return 0;
}