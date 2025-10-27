#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len);

#ifdef __AFL_COMPILER

int main(void) {
  int ret;
  uint8_t buf[64 * 1024];

#ifdef __AFL_LOOP
  while (__AFL_LOOP(10000))
#endif
  {
    ret = fread(buf, 1, sizeof(buf), stdin);
    if (ret < 0) {
      return 0;
    }

    LLVMFuzzerTestOneInput(buf, ret);
  }

  return 0;
}

#else

int main(void) {
  int ret;
  uint8_t buf[64 * 1024];

  ret = fread(buf, 1, sizeof(buf), stdin);
  if (ret < 0) {
    return 0;
  }

  LLVMFuzzerTestOneInput(buf, ret);

  return 0;
}

#endif /* __AFL_COMPILER */
