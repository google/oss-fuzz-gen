#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    int fd;
    const char *file_name = "fuzz_gdbm.db";
    int block_size = 512; // Example block size
    int flags = GDBM_WRCREAT; // Example flags
    void (*fatal_func)(const char *) = abort; // Example fatal function

    // Create a temporary file descriptor with memfd_create
    fd = syscall(SYS_memfd_create, file_name, 0);
    if (fd == -1) {
        perror("memfd_create");
        exit(1);
    }

    // Write the fuzz data to the file descriptor
    if (write(fd, data, size) < size) {
        close(fd);
        perror("write");
        exit(1);
    }

    // Reset the file descriptor offset to the beginning
    if (lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        perror("lseek");
        exit(1);
    }

    // Call the function-under-test
    GDBM_FILE dbf = gdbm_fd_open(fd, file_name, block_size, flags, fatal_func);

    // Close the GDBM file if it was successfully opened
    if (dbf != NULL) {
        gdbm_close(dbf);
    }

    // Close the file descriptor
    close(fd);

    return 0;
}