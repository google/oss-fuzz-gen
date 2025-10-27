/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "toolchain_harness.h"
#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/malloclib.h"

#ifdef TEST_WITH_LIBFUZZER
#include <stddef.h>
#include <stdint.h>
#endif
#ifdef TEST_WITH_KLEE
#include <klee/klee.h>
#endif

size_t libspdm_alignment_size(size_t size) {
  size_t alignment;
  size_t max_buffer_size;

  alignment = LIBSPDM_TEST_ALIGNMENT;
  max_buffer_size = libspdm_get_max_buffer_size();

  /* In the situation where max_buffer_size is not four-byte aligned, reserve sufficient size for the buffer_size */
  if ((size > max_buffer_size - alignment) && (size & (alignment - 1)) != 0) {
    size -= alignment;
  }

  if (((size) & (alignment - 1)) == 3) {
    size += 1;
  }
  if (((size) & (alignment - 1)) == 2) {
    size += 2;
  }
  if (((size) & (alignment - 1)) == 1) {
    size += 3;
  }
  return size;
}

bool libspdm_init_test_buffer(const char *file_name, size_t max_buffer_size, void **test_buffer, size_t *buffer_size) {
  void *buffer;
  FILE *file;
  size_t file_size;
  size_t BytesRead;

  /* 1. Allocate buffer*/
  buffer = malloc(max_buffer_size);
  if (buffer == NULL) {
    return false;
  }

  /* 2. Assign to test_buffer and buffer_size*/
  *test_buffer = buffer;
  if (buffer_size != NULL) {
    *buffer_size = max_buffer_size;
  }

  /* 3. Initialize test_buffer*/
#ifdef TEST_WITH_KLEE
  /* 3.1 For test with KLEE: write symbolic values to test_buffer*/
  klee_make_symbolic((uint8_t *)buffer, max_buffer_size, "buffer");
  return true;
#endif

  file = fopen(file_name, "rb");
  if (file == NULL) {
    fputs("file error", stderr);
    free(buffer);
    exit(1);
  }
  fseek(file, 0, SEEK_END);

  file_size = ftell(file);
  rewind(file);

  if (file_size == 0) {
    printf("\033[1;33m file_size of the seed file is 0, so exit.\033[0m \n");
    free(buffer);
    exit(1);
  }
  file_size = file_size > max_buffer_size ? max_buffer_size : file_size;
  BytesRead = fread((char *)buffer, 1, file_size, file);
  if (BytesRead != file_size) {
    fputs("file error", stderr);
    free(buffer);
    exit(1);
  }
  fclose(file);

  file_size = libspdm_alignment_size(file_size);

  if (buffer_size != NULL) {
    *buffer_size = file_size;
  }

  return true;
}

#ifdef TEST_WITH_LIBFUZZER
#ifdef TEST_WITH_LIBFUZZERWIN
int LLVMFuzzerTestOneInput(const wint_t *data, size_t size)
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
#endif
{
  void *test_buffer;
  size_t max_buffer_size;

  /* 1. Initialize test_buffer*/
  max_buffer_size = libspdm_get_max_buffer_size();
  test_buffer = allocate_zero_pool(max_buffer_size);
  if (test_buffer == NULL) {
    return 0;
  }
  if (size == 0) {
    printf("\033[1;33m file_size of the seed file is 0, so exit.\033[0m \n");
    free(test_buffer);
    return 0;
  }
  if (size > max_buffer_size) {
    size = max_buffer_size;
  } else {
    libspdm_copy_mem(test_buffer, max_buffer_size, data, size);
  }
  size = libspdm_alignment_size(size);
  /* 2. Run test*/
  libspdm_run_test_harness(test_buffer, size);
  /* 3. Clean up*/
  free(test_buffer);
  return 0;
}
#else
int main(int argc, char **argv) {
  bool res;
  void *test_buffer;
  size_t test_buffer_size;
  char *file_name;

  if (argc <= 1) {
    printf("error - missing input file\n");
    exit(1);
  }

  file_name = argv[1];

  /* 1. Initialize test_buffer*/
  res = libspdm_init_test_buffer(file_name, libspdm_get_max_buffer_size(), &test_buffer, &test_buffer_size);
  if (!res) {
    printf("error - fail to init test buffer\n");
    return 0;
  }
  /* 2. Run test*/
  libspdm_run_test_harness(test_buffer, test_buffer_size);
  /* 3. Clean up*/
  free(test_buffer);
  return 0;
}
#endif
