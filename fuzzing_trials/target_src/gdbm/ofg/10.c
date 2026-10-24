#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

// Declare the yylex function
int yylex();

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
  // Create a temporary file to store the fuzz input
  char tmpl[] = "/tmp/fuzzfileXXXXXX";
  int fd = mkstemp(tmpl);
  if (fd == -1) {
    perror("mkstemp");
    return 0;
  }

  // Write the fuzz data to the temporary file
  if (write(fd, data, size) != (ssize_t)size) {
    perror("write");
    close(fd);
    return 0;
  }

  // Reset the file descriptor to the beginning of the file
  if (lseek(fd, 0, SEEK_SET) == -1) {
    perror("lseek");
    close(fd);
    return 0;
  }

  // Redirect the input to the file
  FILE *file = fdopen(fd, "r");
  if (!file) {
    perror("fdopen");
    close(fd);
    return 0;
  }
  stdin = file;

  // Call the function-under-test
  yylex();

  // Clean up
  fclose(file);
  unlink(tmpl);

  return 0;
}