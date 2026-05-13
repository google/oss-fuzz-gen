#include <gdbmtool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
  memcpy(buf, str->string + str->pos, size);
  str->pos += size;
  return size;
}

static void instream_string_close(instream_t istr) {
  struct instream_string *str = (struct instream_string *)istr;
  str->pos = 0;
}

static int instream_string_eq(instream_t a, instream_t b) { return 0; }

static instream_t instream_string_create(const char *input, const char *name) {
  struct instream_string *istr;
  size_t len;
  int nl;

  istr = (struct instream_string *)malloc(sizeof(*istr));
  istr->base.in_name = strdup(name);
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
  istr->string = (char *)malloc(len + nl + 1);
  memcpy(istr->string, input, len);
  if (nl)
    istr->string[len++] = '\n';
  istr->string[len] = 0;
  istr->length = len;
  istr->pos = 0;

  return (instream_t)istr;
}

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
  char *input_buffer = (char *)malloc(size + 1);
  memcpy(input_buffer, data, size);
  input_buffer[size] = '\0';

  instream_t input = instream_string_create(input_buffer, "fuzz_input");
  free(input_buffer);

  gdbmshell(input);

  input->in_close(input);
  free(((struct instream_string *)input)->string);
  free(input->in_name);
  free(input);

  return 0;
}