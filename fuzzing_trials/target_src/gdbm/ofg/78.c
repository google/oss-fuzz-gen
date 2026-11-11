#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>  // Include fcntl.h for O_RDWR
#include <string.h> // Include string.h for memcpy

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    if (size < 2) {
        // If the input size is too small, return early
        return 0;
    }

    char dbname[] = "fuzz_gdbm_sync.db";
    int fd;
    GDBM_FILE db;
    datum key, value;

    // Create a temporary file using memfd_create
    fd = syscall(SYS_memfd_create, dbname, 0);
    if (fd == -1) {
        perror("memfd_create");
        exit(1);
    }

    // Write fuzz data to the file
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

    // Open the GDBM database with a valid file descriptor
    db = gdbm_fd_open(dbname, fd, GDBM_WRCREAT | GDBM_WRITER, 0644, NULL);
    if (!db) {
        close(fd);
        perror("gdbm_fd_open");
        exit(1);
    }

    // Use part of the data as key and value for the database
    key.dptr = (char *)data;
    key.dsize = size / 2;

    value.dptr = (char *)(data + size / 2);
    value.dsize = size - size / 2;

    // Ensure key and value are not null before storing
    if (key.dsize > 0 && value.dsize > 0) {
        // Store the key-value pair in the database
        if (gdbm_store(db, key, value, GDBM_REPLACE) != 0) {
            gdbm_close(db);
            close(fd);
            perror("gdbm_store");
            exit(1);
        }

        // Call the function-under-test
        gdbm_sync(db);

        // Attempt to retrieve the stored value to ensure the database operations are meaningful
        datum retrieved_value = gdbm_fetch(db, key);
        if (retrieved_value.dptr != NULL) {
            // Free the retrieved value
            free(retrieved_value.dptr);
        }
    }

    // Close the GDBM database
    gdbm_close(db);
    close(fd);

    return 0;
}