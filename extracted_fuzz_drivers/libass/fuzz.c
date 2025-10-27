/*
 * Copyright (C) 2022 libass contributors
 *
 * This file is part of libass.
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#include "ass.h"
#include "ass_types.h"
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FUZZMODE_STANDALONE 0
#define FUZZMODE_AFLXX_SHAREDMEM 1
#define FUZZMODE_LIBFUZZER 2
#ifndef ASS_FUZZMODE
#define ASS_FUZZMODE FUZZMODE_STANDALONE
#endif

// MSAN: will trigger MSAN if any pixel in bitmap not written to (costly)
#ifndef ASSFUZZ_HASH_WHOLEBITMAP
#define ASSFUZZ_HASH_WHOLEBITMAP 0
#endif

ASS_Library *ass_library = NULL;
ASS_Renderer *ass_renderer = NULL;
bool quiet = false;

uint8_t hval = 0;

#if ASSFUZZ_HASH_WHOLEBITMAP
static inline void hash(const void *buf, size_t len) {
  const uint8_t *ptr = buf;
  const uint8_t *end = ptr + len;
  while (ptr < end)
    hval ^= *ptr++;
  // MSAN doesn't trigger on the XORs, but will on conditional branches
  if (hval)
    hval ^= 57;
}
#endif

void msg_callback(int level, const char *fmt, va_list va, void *data) {
#if ASS_FUZZMODE == FUZZMODE_STANDALONE
  if (level > 6 || quiet)
    return;
  printf("libass: ");
  vprintf(fmt, va);
  printf("\n");
#else
  // still check for type-mismatches even when not printing
  // (seems to be cheap enough from some simple perormance tests)
  char msg[2048];
  int l = vsnprintf(msg, sizeof(msg), fmt, va) - 1;
  l = l >= sizeof(msg) ? sizeof(msg) - 1 : l;
  l = l < 0 ? 0 : l;
  hval ^= *(msg + l);
#endif
}

static const int RWIDTH = 854;
static const int RHEIGHT = 480;

static bool init_renderer(void) {
  if (ass_renderer)
    return true;

  ass_renderer = ass_renderer_init(ass_library);
  if (!ass_renderer)
    return false;

  ass_set_fonts(ass_renderer, NULL, "sans-serif", ASS_FONTPROVIDER_AUTODETECT, NULL, 1);
  ass_set_frame_size(ass_renderer, RWIDTH, RHEIGHT);
  ass_set_storage_size(ass_renderer, RWIDTH, RHEIGHT);

  return true;
}

static bool init(void) {
  ass_library = ass_library_init();
  if (!ass_library) {
    printf("ass_library_init failed!\n");
    return false;
  }

  ass_set_message_cb(ass_library, msg_callback, NULL);

  if (!init_renderer()) {
    ass_library_done(ass_library);
    ass_library = NULL;
    printf("ass_renderer_init failed!\n");
    return false;
  }

  return true;
}

static inline void process_image(ASS_Image *imgs) {
  for (; imgs; imgs = imgs->next) {
    assert(imgs->w >= 0 && imgs->h >= 0 && imgs->dst_x >= 0 && imgs->dst_y >= 0 && imgs->dst_x + imgs->w <= RWIDTH && imgs->dst_y + imgs->h <= RHEIGHT && imgs->stride >= imgs->w);
#if !ASSFUZZ_HASH_WHOLEBITMAP
    // Check last pixel to probe for out-of-bounds errors
    if (imgs->w && imgs->h)
      hval ^= *(imgs->bitmap + imgs->stride * (imgs->h - 1) + imgs->w - 1);
#else
    unsigned char *src = imgs->bitmap;
    for (int y = 0; y < imgs->h; ++y) {
      hash(src, imgs->w);
      src += imgs->stride;
    }
#endif
  }
}

static void consume_track(ASS_Renderer *renderer, ASS_Track *track) {
  for (int n = 0; n < track->n_events; ++n) {
    int change;
    ASS_Event event = track->events[n];
    process_image(ass_render_frame(ass_renderer, track, event.Start, &change));
    if (event.Duration > 1) {
      process_image(ass_render_frame(ass_renderer, track, event.Start + event.Duration / 2, &change));
      process_image(ass_render_frame(ass_renderer, track, event.Start + event.Duration - 1, &change));
    }
  }
}

#if ASS_FUZZMODE == FUZZMODE_STANDALONE
static ASS_Track *read_track_from_stdin(void) {
  size_t smax = 4096;
  char *buf = malloc(smax);
  if (!buf)
    goto error;
  size_t s = 0;
  ssize_t read_b = 0;
  do {
    // AFL++ docs recommend using raw file descriptors
    // to avoid buffering issues with stdin
    read_b = read(STDIN_FILENO, buf + s, smax - s);
    s += read_b > 0 ? read_b : 0;
    if (s == smax) {
      size_t new_smax = smax > SIZE_MAX / 2 ? SIZE_MAX : smax * 2;
      char *new_buf = realloc(buf, new_smax);
      if (!new_buf || new_smax <= smax) {
        free(new_buf ? new_buf : buf);
        goto error;
      }
      smax = new_smax;
      buf = new_buf;
    }
  } while (read_b > 0);
  buf[s] = '\0';
  ASS_Track *track = ass_read_memory(ass_library, buf, s, NULL);
  free(buf);
  return track;
error:
  printf("Input too large!\n");
  return NULL;
}

int main(int argc, char *argv[]) {
  /* Default failure code of sanitisers is 1, unless
   * changed via env (A|UB|..)SAN_OPTIONS=exitcode=21
   * Except, LLVM's UBSAN always exits with 0 (unless using
   * -fsanitize-undefined-trap-on-error which will SIGILL without an
   * error report being printed), see https://reviews.llvm.org/D35085
   */
  enum {
    FUZZ_OK = 0,
    // SANITISER_FAIL = 1,
    //  Invalid parameters passed etc
    FUZZ_BAD_USAGE = 2,
    // Error before rendering starts
    FUZZ_INIT_ERR = 0
  };

  ASS_Track *track = NULL;
  int retval = FUZZ_OK;

  if (argc < 2 || argc > 3 || (argc == 3 && strcmp(argv[1], "-q"))) {
    printf("usage: %s [-q] <subtitle file>\n", argc ? argv[0] : "fuzz");
    return FUZZ_BAD_USAGE;
  }

  size_t fileidx = 1;
  if (argc == 3) {
    quiet = true;
    fileidx = 2;
  }

  if (!init()) {
    printf("library init failed!\n");
    retval = FUZZ_INIT_ERR;
    goto cleanup;
  }

  if (strcmp(argv[fileidx], "-"))
    track = ass_read_file(ass_library, argv[fileidx], NULL);
  else
    track = read_track_from_stdin();

  if (!track) {
    printf("track init failed!\n");
    retval = FUZZ_INIT_ERR;
    goto cleanup;
  }

  consume_track(ass_renderer, track);

cleanup:
  if (track)
    ass_free_track(track);
  if (ass_renderer)
    ass_renderer_done(ass_renderer);
  if (ass_library)
    ass_library_done(ass_library);

  return retval;
}
#elif ASS_FUZZMODE == FUZZMODE_AFLXX_SHAREDMEM
__AFL_FUZZ_INIT();
/*
 * AFL++ docs recommend to disable optimisation for the main function
 * and GCC and Clang are the only AFL compilers.
 */
#pragma clang optimize off
#pragma GCC optimize("O0")
int main(int argc, char *argv[]) {
  // AFLs buffer and length macros should not be used directly
  ssize_t len;
  unsigned char *buf;

  if (!init()) {
    printf("library init failed!\n");
    return 1;
  }

  __AFL_INIT();
  buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(100000)) {
    len = __AFL_FUZZ_TESTCASE_LEN;

    if (!init_renderer()) {
      printf("Failing renderer init, skipping a sample!\n");
      continue;
    }

    ASS_Track *track = ass_read_memory(ass_library, (char *)buf, len, NULL);
    if (!track)
      continue;
    consume_track(ass_renderer, track);

    ass_free_track(track);
    ass_renderer_done(ass_renderer);
    ass_renderer = NULL;
    ass_clear_fonts(ass_library);
  }

  ass_renderer_done(ass_renderer);
  ass_library_done(ass_library);

  return 0;
}
#elif ASS_FUZZMODE == FUZZMODE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ASS_Track *track = NULL;

  // All return values but zero are reserved
  if (!init())
    return 0;

  track = ass_read_memory(ass_library, (char *)data, size, NULL);
  if (track) {
    consume_track(ass_renderer, track);
    ass_free_track(track);
  }

  ass_renderer_done(ass_renderer);
  ass_library_done(ass_library);
  ass_renderer = NULL;
  ass_library = NULL;

  return 0;
}
#else
#error Unknown fuzzer mode selected!
#endif
