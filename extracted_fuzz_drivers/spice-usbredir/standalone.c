/* standalone.c -- libFuzzer-compatible main function

   Copyright 2021 Michael Hanselmann

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Forward declare the "fuzz target" interface. We deliberately keep this
// interface simple and header-free.
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
  const char *path;
  int fd;
  ssize_t length;
  uint8_t *buf;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input-file...>\n", argv[0]);
    exit(2);
  }

  for (int i = 1; i < argc; i++) {
    path = argv[i];

    fd = open(path, O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "Opening \"%s\": %s\n", path, strerror(errno));
      exit(1);
    }

    length = lseek(fd, 0, SEEK_END);
    if (length < 0) {
      fprintf(stderr, "Seeking end of \"%s\": %s\n", path, strerror(errno));
      exit(1);
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
      fprintf(stderr, "Seeking beginning of \"%s\": %s\n", path, strerror(errno));
      exit(1);
    }

    fprintf(stderr, "Reading %zd bytes from \"%s\"\n", length, path);

    // Allocate exactly length bytes so that we reliably catch buffer
    // overflows.
    buf = malloc(length);

    if (read(fd, buf, length) != length) {
      fprintf(stderr, "Reading %zd bytes from \"%s\": %s\n", length, path, strerror(errno));
      exit(1);
    }

    close(fd);

    LLVMFuzzerTestOneInput(buf, length);

    fprintf(stderr, "Execution successful\n");

    free(buf);
  }

  return 0;
}

/* vim: set sw=4 sts=4 et : */
