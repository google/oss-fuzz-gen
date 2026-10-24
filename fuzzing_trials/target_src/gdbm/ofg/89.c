#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
  GDBM_FILE dbf;
  char tmpl[] = "/tmp/fuzzdbXXXXXX";
  int fd;
  unsigned long loaded_entries = 0;
  int flags = GDBM_WRCREAT;
  int mode = 0644;

  // Create a temporary file to be used as a database
  fd = mkstemp(tmpl);
  if (fd == -1) {
    perror("mkstemp");
    return 0;
  }

  // Write the fuzz data to the temporary file
  if (write(fd, data, size) != (ssize_t)size) {
    perror("write");
    close(fd);
    unlink(tmpl);
    return 0;
  }

  // Close the file descriptor
  close(fd);

  // Open the GDBM database
  dbf = gdbm_open(tmpl, 0, flags, mode, NULL);
  if (!dbf) {
    perror("gdbm_open");
    unlink(tmpl);
    return 0;
  }

  // Call the function-under-test
  gdbm_load(dbf, tmpl, 0, 0, &loaded_entries);

  // Close and unlink the database
  gdbm_close(dbf);
  unlink(tmpl);

  return 0;
}