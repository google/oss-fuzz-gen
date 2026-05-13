#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    int fd;
    GDBM_FILE dbf;
    size_t bucket_count;

    // Create an in-memory file descriptor using memfd_create
    fd = syscall(SYS_memfd_create, "fuzzdb", 0);
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

    // Open the GDBM file using the file descriptor
    dbf = gdbm_fd_open(fd, 0, GDBM_READER, 0, NULL);
    if (dbf == NULL) {
        close(fd);
        return 0; // If the file couldn't be opened, return early
    }

    // Call the function-under-test
    gdbm_bucket_count(dbf, &bucket_count);

    // Close the GDBM file
    gdbm_close(dbf);

    // Close the file descriptor
    close(fd);

    return 0;
}