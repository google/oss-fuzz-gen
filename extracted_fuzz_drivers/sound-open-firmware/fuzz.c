// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2024 Google LLC.  All rights reserved.
// Author: Andy Ross <andyross@google.com>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <irq_ctrl.h>
#include <zephyr/sys/time_units.h>

/* Zephyr arch APIs, not in a header (native_sim has them though) */
void posix_init(int argc, char *argv[]);
void posix_exec_for(uint64_t us);

const uint8_t *posix_fuzz_buf;
size_t posix_fuzz_sz;

/**
 * Entry point for fuzzing. Works by placing the data
 * into two known symbols, triggering an app-visible interrupt, and
 * then letting the simulator run for a fixed amount of time (intended to be
 * "long enough" to handle the event and reach a quiescent state
 * again)
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t sz) {
  static bool runner_initialized;

  if (!runner_initialized) {
    posix_init(0, NULL);
    runner_initialized = true;
  }

  /* Provide the fuzz data to the embedded OS as an interrupt, with
   * "DMA-like" data placed into native_fuzz_buf/sz
   */
  posix_fuzz_buf = (void *)data;
  posix_fuzz_sz = sz;
  hw_irq_ctrl_set_irq(CONFIG_ZEPHYR_POSIX_FUZZ_IRQ);

  /* Give the OS time to process whatever happened in that
   * interrupt and reach an idle state.
   */
  posix_exec_for(k_ticks_to_us_ceil64(CONFIG_ZEPHYR_POSIX_FUZZ_TICKS));
  return 0;
}
