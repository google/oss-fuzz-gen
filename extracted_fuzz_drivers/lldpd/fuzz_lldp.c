/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2023 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "../src/daemon/lldpd.h"

#define kMinInputLength 5
#define kMaxInputLength 2048

/* Use this callback to avoid some logs */
void donothing(int pri, const char *msg) {};

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 1;
  }

  struct lldpd_chassis *nchassis = NULL;
  struct lldpd_port *nport = NULL;
  struct lldpd_hardware hardware;

  log_register(donothing);

  lldp_decode(NULL, (char *)Data, Size, &hardware, &nchassis, &nport);

  if (!nchassis || !nport) {
    return 1;
  }

  lldpd_port_cleanup(nport, 1);
  free(nport);
  lldpd_chassis_cleanup(nchassis, 1);

  return 0;
}
