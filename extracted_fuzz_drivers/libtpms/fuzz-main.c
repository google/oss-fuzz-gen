#include <stdio.h>
#include <stdlib.h>

#define MIN_NUMBER_OF_RUNS 4
#define EXIT_TEST_SKIP 77

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char **argv) {
  int i, j;

  for (i = 1; i < argc; i++) {
    char *name = argv[i];
    ssize_t size;
    FILE *f = fopen(name, "rb");
    char *buf;

    fprintf(stdout, "%s...\n", name);
    if (f == NULL) {
      perror("fopen() failed");
      continue;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    if (size < 0) {
      fclose(f);
      perror("ftell() failed");
      continue;
    }
    fseek(f, 0, SEEK_SET);
    buf = malloc(size + 1);
    if (fread(buf, 1, size, f) != (size_t)size) {
      fclose(f);
      perror("fread() failed");
      continue;
    }
    fclose(f);
    buf[size] = 0;

    for (j = 0; j < MIN_NUMBER_OF_RUNS; j++) {
      if (LLVMFuzzerTestOneInput((void *)buf, size) == EXIT_TEST_SKIP) {
        return EXIT_TEST_SKIP;
      }
    }
    free(buf);
  }

  return EXIT_SUCCESS;
}
