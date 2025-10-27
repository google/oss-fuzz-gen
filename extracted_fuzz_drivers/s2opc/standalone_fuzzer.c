/*
 * Licensed to Systerel under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Systerel licenses this file to you under the Apache
 * License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "sopc_mem_alloc.h"

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

static bool read_all(FILE *fd, unsigned char *data, size_t len) {
  size_t n = 0;

  while (true) {
    size_t read = fread(data + n, sizeof(unsigned char), len - n, fd);
    n += read;

    if (read == 0 || n == len) {
      break;
    }
  }

  int err = ferror(fd);

  if (err != 0) {
    fprintf(stderr, "Error while reading: %s\n", strerror(err));
    return false;
  }

  return true;
}

static bool fuzz_file(FILE *fd) {
  if (fseek(fd, 0, SEEK_END) == -1) {
    perror("Cannot seek to the end of file");
    return false;
  }

  long len = ftell(fd);

  if (len == -1) {
    perror("ftell");
    return false;
  }

  if (fseek(fd, 0, SEEK_SET) == -1) {
    perror("Cannot rewind the file");
    return false;
  }

  unsigned char *buf = SOPC_Malloc((size_t)len);

  if (buf == NULL) {
    fprintf(stderr, "Memory allocation failure\n");
    return false;
  }

  if (!read_all(fd, buf, (size_t)len)) {
    return false;
  }

  LLVMFuzzerTestOneInput(buf, (size_t)len);
  SOPC_Free(buf);

  fprintf(stderr, "Done (%ld bytes)\n", len);

  return true;
}

int main(int argc, char **argv) {
  fprintf(stderr, "Running the fuzzing function on %d inputs\n", argc - 1);

  for (int i = 1; i < argc; i++) {
    const char *filename = argv[i];

    fprintf(stderr, "Running: %s\n", filename);

    FILE *fd = fopen(filename, "r");

    if (fd == NULL) {
      fprintf(stderr, "Cannot open %s: %s\n", filename, strerror(errno));
      return 1;
    }

    bool ok = fuzz_file(fd);
    fclose(fd);

    if (!ok) {
      return 1;
    }
  }
}
