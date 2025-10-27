/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <fcntl.h> /* open() O_RDONLY O_BINARY */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
/*
 * Libdwarf library callers can only use these headers.
 */
#include "dwarf.h"
#include "libdwarf.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Fuzzer function
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  int fuzz_fd = 0;
  Dwarf_Ptr errarg = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Error *errp = NULL;
  Dwarf_Debug dbg = 0;
  off_t size_left = 0;
  off_t fsize = 0;
  ssize_t readlen = 1000;
  ssize_t readval = 0;
  unsigned char *readbuf = 0;
  unsigned int tcrc = 0;
  unsigned int init = 0;

  fuzz_fd = open(filename, O_RDONLY | O_BINARY);
  fsize = size_left = lseek(fuzz_fd, 0L, SEEK_END);
  readbuf = (unsigned char *)malloc(readlen);
  /*  The read below will fail, so to avoid
      reading uninitialized data we ensure
      the data is initialized. */
  memset((void *)readbuf, 10, (size_t)readlen);
  if (fuzz_fd != -1) {
    while (size_left > 0) {
      if (size_left < readlen) {
        readlen = size_left;
      }
      readval = read(fuzz_fd, readbuf, readlen);
      if (readval != readlen) {
        /*  The read failed as it is expected to. */
      }
      size_left -= readlen;
      tcrc = dwarf_basic_crc32(readbuf, readlen, init);
      init = tcrc;
    }
  }
  free(readbuf);
  close(fuzz_fd);
  unlink(filename);
  return 0;
}
