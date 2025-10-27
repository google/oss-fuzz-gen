//
// liblouis Braille Translation and Back-Translation Library
//
// Copyright (C) 2022 Anna Stan, Nicolas Morel, Kalilou Mamadou Dramé
//
// This file is part of liblouis.
//
// liblouis is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published
// by the Free Software Foundation, either version 2.1 of the License, or
// (at your option) any later version.
//
// liblouis is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with liblouis. If not, see <http://www.gnu.org/licenses/>.
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <internal.h>
#include <liblouis.h>

#define LANGUAGE "en"

static int initialized = 0;

#define BOLDRED(x) "\x1b[31m\x1b[1m" x "\x1b[0m"

static const char *table_default;

static void __attribute__((destructor)) free_ressources(void) { lou_free(); }

void avoid_log(logLevels level, const char *msg) {
  (void)level;
  (void)msg;
}

extern int LLVMFuzzerRunDriver(int *argc, char ***argv, int (*UserCb)(const uint8_t *Data, size_t Size));

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int inputLen = 0;
  int outputLen = 0;
  char *mutable_data = NULL;

  if (!initialized) {
    lou_registerLogCallback(avoid_log);
    table_default = getenv("FUZZ_TABLE");
    initialized = 1;
  }

  mutable_data = strndup((char *)data, size);
  if (!mutable_data) {
    perror("malloc");
    exit(1);
  }

  widechar *inputText = malloc((size * 16 + 1) * sizeof(widechar));
  int len = (int)_lou_extParseChars(mutable_data, inputText);
  free(mutable_data);
  if (len <= 0) {
    free(inputText);
    return -1;
  }

  assert(len <= (size * 16));
  inputLen = len;
  outputLen = len * 16;
  widechar *outputText = malloc((outputLen + 1) * sizeof(widechar));
  if (table_default == NULL) {
    fprintf(stderr, "\n" BOLDRED("[Please set up FUZZ_TABLE env var before starting fuzzer]") "\nThis environment variable is supposed to contain the table you want to test with lou_translateString()\n\n");
    exit(0);
  }
  lou_translateString(table_default, inputText, &inputLen, outputText, &outputLen, NULL, NULL, ucBrl);
  free(inputText);
  free(outputText);

  return 0;
}

int main(int argc, char *argv[]) { LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput); }
