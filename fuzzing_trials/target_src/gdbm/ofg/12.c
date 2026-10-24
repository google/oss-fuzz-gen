#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gdbm.h>
#include <time.h> // Include for struct timespec

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    struct gdbm_open_spec spec;
    char *filename;

    // Ensure size is sufficient to create a non-NULL string
    if (size < 2) {
        return 0;
    }

    // Allocate memory for filename
    filename = (char *)malloc(size + 1);

    // Copy data into filename ensuring null-termination
    memcpy(filename, data, size);
    filename[size] = '\0';

    // Initialize the gdbm_open_spec structure
    spec.fd = -1; // Use -1 as per the structure definition
    spec.mode = 0; // Default mode
    spec.block_size = 512; // Example block size
    spec.lock_wait = GDBM_LOCKWAIT_NONE; // Example lock wait mode
    spec.lock_timeout.tv_sec = 0; // No timeout
    spec.lock_timeout.tv_nsec = 0;
    spec.lock_interval.tv_sec = 0;
    spec.lock_interval.tv_nsec = 0;
    spec.fatal_func = NULL; // No fatal function

    // Call the function-under-test with the correct number of arguments
    GDBM_FILE dbf = gdbm_open_ext(filename, GDBM_WRCREAT, &spec);

    // Close the database if it was opened
    if (dbf != NULL) {
        gdbm_close(dbf);
    }

    // Free allocated memory
    free(filename);

    return 0;
}