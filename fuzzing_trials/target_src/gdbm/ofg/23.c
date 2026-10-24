#include <gdbm.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    int fd;
    GDBM_FILE db;

    // Create an in-memory file descriptor
    fd = syscall(SYS_memfd_create, "gdbm_fuzz", 0);
    if (fd == -1) {
        perror("memfd_create");
        exit(1);
    }

    // Write the fuzz data to the in-memory file
    if (write(fd, data, size) < size) {
        close(fd);
        perror("write");
        exit(1);
    }

    // Reset the file offset to the beginning
    if (lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        perror("lseek");
        exit(1);
    }

    // Open the GDBM database using the file descriptor
    db = gdbm_fd_open(fd, 0, GDBM_WRCREAT, 0666, NULL);
    if (db == NULL) {
        close(fd);
        return 0;
    }

    // Call the function-under-test
    gdbm_clear_error(db);

    // Close the GDBM database
    gdbm_close(db);

    // Close the file descriptor
    close(fd);

    return 0;
}