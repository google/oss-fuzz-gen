#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include for mkstemp, write, close, and unlink

int LLVMFuzzerTestOneInput_189(const uint8_t *data, size_t size) {
  if (size < 2) return 0; // Ensure there's enough data for non-empty strings

  // Create temporary filenames for the function parameters
  char db_filename[] = "/tmp/gdbm_fuzz_dbXXXXXX";
  char snapshot_filename[] = "/tmp/gdbm_fuzz_snapshotXXXXXX";

  // Create temporary files
  int db_fd = mkstemp(db_filename);
  int snapshot_fd = mkstemp(snapshot_filename);

  if (db_fd == -1 || snapshot_fd == -1) {
    perror("mkstemp");
    return 0;
  }

  // Write some data to the files to ensure they are not empty
  write(db_fd, data, size / 2);
  write(snapshot_fd, data + size / 2, size - size / 2);

  // Close the file descriptors
  close(db_fd);
  close(snapshot_fd);

  // Prepare the output parameter
  const char *latest_snapshot = NULL;

  // Call the function-under-test
  gdbm_latest_snapshot(db_filename, snapshot_filename, &latest_snapshot);

  // Clean up
  unlink(db_filename);
  unlink(snapshot_filename);

  return 0;
}