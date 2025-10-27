// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup LUKS2 fuzz target
 *
 * Copyright (C) 2022-2024 Daniel Zatovic <daniel.zatovic@gmail.com>
 * Copyright (C) 2022-2024 Red Hat, Inc. All rights reserved.
 */

extern "C" {
#define FILESIZE (16777216)
#include "FuzzerInterface.h"
#include "crypto_backend/crypto_backend.h"
#include "luks2/luks2.h"
#include "src/cryptsetup.h"

#define CHKSUM_ALG "sha256"
#define CHKSUM_SIZE 32

static bool fix_checksum_hdr(struct luks2_hdr_disk *hdr, const char *data, size_t len) {
  char *csum = (char *)&hdr->csum;
  struct crypt_hash *hd = NULL;
  bool r = false;

  if (crypt_hash_init(&hd, CHKSUM_ALG))
    return false;

  memset(csum, 0, LUKS2_CHECKSUM_L);

  if (!crypt_hash_write(hd, data, len) && !crypt_hash_final(hd, csum, CHKSUM_SIZE))
    r = true;

  crypt_hash_destroy(hd);
  return r;
}

static bool calculate_checksum(const char *data, size_t size, struct luks2_hdr_disk *hdr_rw) {
  uint64_t hdr_size;

  /* Primary header cannot fit in data */
  if (sizeof(*hdr_rw) > size)
    return false;

  hdr_size = be64_to_cpu(((struct luks2_hdr_disk *)data)->hdr_size);
  if (hdr_size > size || hdr_size <= sizeof(*hdr_rw))
    return false;

  /* Calculate checksum for primary header */
  memcpy(hdr_rw, data, sizeof(*hdr_rw));
  return fix_checksum_hdr(hdr_rw, data, (size_t)hdr_size);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int fd, r = EXIT_FAILURE;
  struct crypt_device *cd = NULL;
  char name[] = "/tmp/test-script-fuzz.XXXXXX";
  struct luks2_hdr_disk hdr_rw;
  size_t modified_data_size;

  /* if csum calculation fails, keep fuzzer running on original input */
  if (size >= sizeof(hdr_rw) && calculate_checksum((const char *)data, size, &hdr_rw))
    modified_data_size = sizeof(hdr_rw);
  else
    modified_data_size = 0;

  /* create file with LUKS header for libcryptsetup */
  fd = mkostemp(name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC);
  if (fd == -1)
    return r;

  /* enlarge header */
  if (ftruncate(fd, FILESIZE) == -1)
    goto out;

  if (modified_data_size && write_buffer(fd, &hdr_rw, modified_data_size) != (ssize_t)modified_data_size)
    goto out;

  if (write_buffer(fd, data + modified_data_size, size - modified_data_size) != (ssize_t)size)
    goto out;

  /* Actual fuzzing */
  if (crypt_init(&cd, name) == 0)
    (void)crypt_load(cd, CRYPT_LUKS2, NULL);
  crypt_free(cd);
  r = 0;
out:
  close(fd);
  unlink(name);

  return r;
}
}
