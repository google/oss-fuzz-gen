#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
  GDBM_FILE dbf;
  const char *filename = "fuzz_test.gdbm";
  int block_size = 512; // Arbitrary non-zero block size
  int mode = GDBM_WRCREAT; // Open for reading and writing, create if necessary
  unsigned long num_records = 0;

  // Create a temporary file to simulate a GDBM file
  FILE *temp_file = fopen(filename, "wb");
  if (!temp_file) {
    perror("fopen");
    return 0;
  }

  // Write fuzz data to the file
  if (fwrite(data, 1, size, temp_file) != size) {
    perror("fwrite");
    fclose(temp_file);
    return 0;
  }
  fclose(temp_file);

  // Open the GDBM file
  dbf = gdbm_open(filename, block_size, mode, 0666, NULL);
  if (!dbf) {
    fprintf(stderr, "gdbm_open failed: %s\n", gdbm_strerror(gdbm_errno));
    return 0;
  }

  // Call the function-under-test
  gdbm_load(dbf, filename, block_size, mode, &num_records);

  // Close the GDBM file
  gdbm_close(dbf);

  // Remove the temporary file
  unlink(filename);

  return 0;
}