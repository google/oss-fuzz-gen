#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    GDBM_FILE dbf;
    gdbm_error error_code;
    int line_number;

    // Create a temporary in-memory file using memfd_create
    int fd = syscall(SYS_memfd_create, "fuzz_gdbm", 0);
    if (fd == -1) {
        return 0; // Exit if memfd_create fails
    }

    // Write the input data to the file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0; // Exit if write fails
    }

    // Open the GDBM database
    dbf = gdbm_fd_open("fuzz_gdbm", 512, GDBM_NEWDB, 0666, NULL);
    if (!dbf) {
        close(fd);
        return 0; // Exit if gdbm_fd_open fails
    }

    // Use the first byte of data to determine the error code
    error_code = (gdbm_error)(data[0] % 4); // Assuming there are 4 error codes

    // Use the second byte of data to determine the line number
    line_number = (int)(data[1]);

    // Call the function under test
    gdbm_set_errno(dbf, error_code, line_number);

    // Close the GDBM file
    gdbm_close(dbf);
    close(fd);

    return 0;
}