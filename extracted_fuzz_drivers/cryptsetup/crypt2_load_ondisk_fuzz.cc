// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup LUKS1, FileVault, BitLocker fuzz target
 */

extern "C" {
#define FILESIZE (16777216)
#include "FuzzerInterface.h"
#include "crypto_backend/crypto_backend.h"
#include "luks1/luks.h"
#include "src/cryptsetup.h"
#include <err.h>

void empty_log(int level, const char *msg, void *usrptr) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int fd, r;
  struct crypt_device *cd = NULL;
  char name[] = "/tmp/test-script-fuzz.XXXXXX";

  fd = mkostemp(name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC);
  if (fd == -1)
    err(EXIT_FAILURE, "mkostemp() failed");

  /* enlarge header */
  if (ftruncate(fd, FILESIZE) == -1)
    goto out;

  if (write_buffer(fd, data, size) != (ssize_t)size)
    goto out;

  crypt_set_log_callback(NULL, empty_log, NULL);

  if (crypt_init(&cd, name) == 0) {
    r = crypt_load(cd, CRYPT_LUKS1, NULL);
    if (r == 0)
      goto out;

    r = crypt_load(cd, CRYPT_FVAULT2, NULL);
    if (r == 0)
      goto out;

    (void)crypt_load(cd, CRYPT_BITLK, NULL);
  }
out:
  crypt_free(cd);
  close(fd);
  unlink(name);
  return 0;
}
}
