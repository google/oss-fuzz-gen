#define _FILE_OFFSET_BITS 64
#include "huff_codes.h"
#include "igzip_lib.h"
#include "test.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char *argv[]) {
  FILE *in = NULL;
  unsigned char *in_buf = NULL;
  uint64_t in_file_size;

  if (argc != 2) {
    fprintf(stderr, "Usage: isal_fuzz_inflate <infile>\n");
    exit(1);
  }
  in = fopen(argv[1], "rb");
  if (!in) {
    fprintf(stderr, "Can't open %s for reading\n", argv[1]);
    exit(1);
  }
  in_file_size = get_filesize(in);
  in_buf = malloc(in_file_size);

  if (in_buf == NULL) {
    fprintf(stderr, "Failed to malloc input and outputs buffers\n");
    exit(1);
  }

  if (fread(in_buf, 1, in_file_size, in) != in_file_size) {
    fprintf(stderr, "Failed to read from %s\n", argv[1]);
    exit(1);
  }

  return LLVMFuzzerTestOneInput(in_buf, in_file_size);
}
