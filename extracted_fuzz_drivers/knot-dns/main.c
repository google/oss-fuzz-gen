/* Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 * Copyright (C) 2017 Tim Ruehsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#ifndef __AFL_LOOP

#include <dirent.h>

static void test_all_from(const char *dirname) {
  DIR *dirp = opendir(dirname);
  if (dirp == NULL) {
    return;
  }

  struct dirent *dp;
  while ((dp = readdir(dirp))) {
    if (*dp->d_name == '.') {
      continue;
    }

    char fname[strlen(dirname) + strlen(dp->d_name) + 2];
    int ret = snprintf(fname, sizeof(fname), "%s/%s", dirname, dp->d_name);
    if (ret < 0 || ret >= sizeof(fname)) {
      fprintf(stderr, "Invalid path %s/%s\n", dirname, dp->d_name);
    }

    int fd;
    if ((fd = open(fname, O_RDONLY)) == -1) {
      fprintf(stderr, "Failed to open %s (%d)\n", fname, errno);
      continue;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
      fprintf(stderr, "Failed to stat %d (%d)\n", fd, errno);
      close(fd);
      continue;
    }

    uint8_t *data = malloc(st.st_size);
    if (data == NULL) {
      fprintf(stderr, "Failed to stat %d (%d)\n", fd, ENOMEM);
      close(fd);
      continue;
    }

    ssize_t n;
    if ((n = read(fd, data, st.st_size)) == st.st_size) {
      printf("testing %llu bytes from '%s'\n", (unsigned long long)st.st_size, fname);
      fflush(stdout);
      LLVMFuzzerTestOneInput(data, st.st_size);
      fflush(stderr);
    } else {
      fprintf(stderr, "Failed to read %llu bytes from %s (%d), got %zd\n", (unsigned long long)st.st_size, fname, errno, n);
    }

    free(data);
    close(fd);
  }
  closedir(dirp);
}

int main(int argc, char **argv) {
  const char *target = strrchr(argv[0], '/');
  target = target ? target + 1 : argv[0];

  char corporadir[sizeof(SRCDIR) + 1 + strlen(target) + 8];

  if (strncmp(target, "lt-", 3) == 0) {
    target += 3;
  }

  int ret = snprintf(corporadir, sizeof(corporadir), SRCDIR "/%s.in", target);
  if (ret < 0 || ret >= sizeof(corporadir)) {
    fprintf(stderr, "Invalid path %s/%s\n", SRCDIR "/%s.in", target);
  }

  test_all_from(corporadir);

  ret = snprintf(corporadir, sizeof(corporadir), SRCDIR "/%s.repro", target);
  if (ret < 0 || ret >= sizeof(corporadir)) {
    fprintf(stderr, "Invalid path %s/%s\n", SRCDIR "/%s.repro", target);
  }

  test_all_from(corporadir);

  return 0;
}

#else

int main(int argc, char **argv) {
  unsigned char buf[64 * 1024];

  while (__AFL_LOOP(10000)) {
    int ret = fread(buf, 1, sizeof(buf), stdin);
    if (ret < 0) {
      return 0;
    }

    LLVMFuzzerTestOneInput(buf, ret);
  }

  return 0;
}

#endif /* __AFL_LOOP */
