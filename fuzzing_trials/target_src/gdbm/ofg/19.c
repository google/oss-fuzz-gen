#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    int fd;
    GDBM_FILE db;
    size_t bucket_count;
    char dbname[] = "fuzz_gdbm.db";

    // Create an in-memory file descriptor using memfd_create
    fd = syscall(SYS_memfd_create, dbname, 0);
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

    // Reset file offset to the beginning
    if (lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        perror("lseek");
        exit(1);
    }

    // Open the GDBM database using the in-memory file descriptor
    db = gdbm_fd_open(dbname, 0, GDBM_WRCREAT, 0644, NULL);
    if (!db) {
        close(fd);
        fprintf(stderr, "gdbm_fd_open failed\n");
        return 0;
    }

    // Call the function-under-test
    gdbm_bucket_count(db, &bucket_count);

    // Clean up
    gdbm_close(db);
    close(fd);

    return 0;
}