#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
  char filename[] = "/tmp/fuzzdbXXXXXX";
  int file_mode = 0644; // File mode with read/write permissions
  int flags = GDBM_WRCREAT; // Open for reading and writing, create if not exists
  int block_size = 512; // Default block size
  GDBM_FILE db;

  // Create a temporary file
  int fd = mkstemp(filename);
  if (fd == -1) {
    perror("mkstemp");
    return 0;
  }

  // Write the fuzz data to the file
  if (write(fd, data, size) != (ssize_t)size) {
    perror("write");
    close(fd);
    unlink(filename);
    return 0;
  }

  // Close the file descriptor
  close(fd);

  // Open the GDBM database
  db = gdbm_open(filename, block_size, flags, file_mode, NULL);

  // Check if the database was opened successfully
  if (db != NULL) {
    // Close the database
    gdbm_close(db);
  }

  // Clean up the temporary file
  unlink(filename);

  return 0;
}