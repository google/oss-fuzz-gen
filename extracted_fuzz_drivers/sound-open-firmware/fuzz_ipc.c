// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2020, Google Inc. All rights reserved
//
// Author: Curtis Malainey <cujomalainey@chromium.org>

#include <inttypes.h>
#include <sof/audio/component_ext.h>
#include <sof/ipc/driver.h>
#include <sof/lib/notifier.h>
#include <sof/math/numbers.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerInitialize(int *argc, char ***argv);
// fuzz_ipc.c
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // since we can always assume the mailbox is allocated
  // copy the buffer to pre allocated buffer
  struct sof_ipc_cmd_hdr *hdr = calloc(SOF_IPC_MSG_MAX_SIZE, 1);

  memcpy_s(hdr, SOF_IPC_MSG_MAX_SIZE, Data, MIN(Size, SOF_IPC_MSG_MAX_SIZE));

  // sanity check performed typically by platform dependent code
  if (hdr->size < sizeof(*hdr) || hdr->size > SOF_IPC_MSG_MAX_SIZE)
    goto done;

  ipc_cmd((struct ipc_cmd_hdr *)hdr);
done:
  free(hdr);
  return 0; // Non-zero return values are reserved for future use.
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  init_system_notify(sof_get());

  trace_init(sof_get());

  platform_init(sof_get());

  /* init components */
  sys_comp_init(sof_get());

  /* init self-registered modules */
  /* sys_module_init(); */

  /* other necessary initializations, todo: follow better SOF init */
  pipeline_posn_init(sof_get());

  return 0;
}
