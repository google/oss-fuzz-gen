/* This file is part of GDBM, the GNU data base manager.
   Copyright (C) 2021-2023 Free Software Foundation, Inc.

   GDBM is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GDBM is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GDBM. If not, see <http://www.gnu.org/licenses/>.    */

#include <gdbmtool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static char dbname[] = "a.db";
static char fuzz_rc_name[] = "gdbm_fuzzer.rc";

struct instream_string {
  struct instream base;
  char *string;
  size_t length;
  size_t pos;
};

static ssize_t instream_string_read(instream_t istr, char *buf, size_t size) {
  struct instream_string *str = (struct instream_string *)istr;
  size_t n = str->length - str->pos;
  if (size > n)
    size = n;
  memcpy(buf, str->string + str->pos, n);
  str->pos += n;
  return n;
}

static void instream_string_close(instream_t istr) {
  struct instream_string *str = (struct instream_string *)istr;
  str->pos = 0;
}

static int instream_string_eq(instream_t a, instream_t b) { return 0; }

static instream_t instream_string_create(char const *input, char const *name) {
  struct instream_string *istr;
  size_t len;
  int nl;

  istr = emalloc(sizeof(*istr));
  istr->base.in_name = estrdup(name);
  istr->base.in_inter = 0;
  istr->base.in_read = instream_string_read;
  istr->base.in_close = instream_string_close;
  istr->base.in_eq = instream_string_eq;
  istr->base.in_history_size = NULL;
  istr->base.in_history_get = NULL;
  len = strlen(input);
  while (len > 0 && (input[len - 1] == ' ' || input[len - 1] == '\t'))
    --len;

  nl = len > 0 && input[len - 1] != '\n';
  istr->string = emalloc(len + nl + 1);
  memcpy(istr->string, input, len);
  if (nl)
    istr->string[len++] = '\n';
  istr->string[len] = 0;
  istr->length = len;
  istr->pos = 0;

  return (instream_t)istr;
}

static instream_t input;

static void fuzzer_exit(void) {
  struct instream_string *istr = (struct instream_string *)input;
  free(istr->string);
  free(input->in_name);
  free(input);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  char *argv0 = (*argv)[0];
  char *p, *file_name;
  size_t len;
  struct stat st;
  char *input_buffer;
  FILE *fp;

  /* Initialize gdbmshell globals */
  set_progname("gdbmfuzz");

  /* Build full rc file name */
  p = strrchr(argv0, '/');
  len = p - argv0;
  file_name = emalloc(len + 1 + strlen(fuzz_rc_name) + 1);
  memcpy(file_name, argv0, len);
  file_name[len++] = '/';
  strcpy(file_name + len, fuzz_rc_name);

  /* Read the file */
  if (stat(file_name, &st)) {
    terror("can't stat %s: %s", file_name, strerror(errno));
    exit(1);
  }

  input_buffer = emalloc(st.st_size + 1);
  fp = fopen(file_name, "r");
  if (!fp) {
    terror("can't open %s: %s", file_name, strerror(errno));
    exit(1);
  }
  if (fread(input_buffer, st.st_size, 1, fp) != 1) {
    terror("error reading from %s: %s", file_name, strerror(errno));
    exit(1);
  }
  input_buffer[st.st_size] = 0;
  fclose(fp);

  /* Set up the input stream */
  input = instream_string_create(input_buffer, file_name);
  free(file_name);
  free(input_buffer);
  if (!input)
    exit(1);

  atexit(fuzzer_exit);

  /* Disable usual gdbmshell output. */
  stdout = fopen("/dev/null", "w");
  if (!stdout) {
    terror("can't open %s: %s", "/dev/null", strerror(errno));
    exit(1);
  }

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int fd;
  GDBM_FILE db;

  fd = syscall(SYS_memfd_create, dbname, 0);
  if (fd == -1) {
    perror("memfd_create");
    exit(1);
  }

  if (write(fd, data, size) < size) {
    close(fd);
    perror("write");
    exit(1);
  }

  if (lseek(fd, 0, SEEK_SET) != 0) {
    close(fd);
    perror("write");
    exit(1);
  }

  variable_set("filename", VART_STRING, dbname);
  variable_set("fd", VART_INT, &fd);

  return gdbmshell(input);
}
