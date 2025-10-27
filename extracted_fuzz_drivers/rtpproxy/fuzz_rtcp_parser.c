#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "rtcp2json.h"
#include "rtp_packet.h"
#include "rtpp_module.h"
#include "rtpp_module_if_static.h"
#include "rtpp_sbuf.h"

#include "fuzz_standalone.h"

__attribute__((constructor)) void fuzz_rtcp_parser_init() {
  struct rtpp_minfo *mip;

  mip = rtpp_static_modules_lookup("acct_rtcp_hep");
  assert(mip != NULL);
  mip->_malloc = &malloc;
  mip->_realloc = &realloc;
  mip->_free = &free;
}

int LLVMFuzzerTestOneInput(const char *rtcp_data, size_t rtcp_dlen) {
  struct rtpp_sbuf *sbp;

  if (rtcp_dlen > MAX_RPKT_LEN)
    return (0);

  sbp = rtpp_sbuf_ctor(512);
  assert(sbp != NULL);
#if 0
    for (size_t i = 0; i < rtcp_dlen; i++) {
        char bf[3];
        sprintf(bf, "%.2x", rtcp_data[i]);
        write(STDERR_FILENO, bf, 2);
    }
    write(STDERR_FILENO, "\n", 1);
    fsync(STDERR_FILENO);
#endif
  rtcp2json(sbp, rtcp_data, rtcp_dlen);
  rtpp_sbuf_dtor(sbp);

  return (0);
}
