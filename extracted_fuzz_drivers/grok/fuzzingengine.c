/*
 *    Copyright (C) 2016-2023 Grok Image Compression Inc.
 *
 *    This source code is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This source code is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

// fuzzer forward declarations
int LLVMFuzzerTestOneInput(void *buf, size_t len);
int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char *argv[]) {
  // parse command line args
  LLVMFuzzerInitialize(&argc, &argv);

  // handle absent file name
  if (argc < 2)
    return LLVMFuzzerTestOneInput(" ", 1);

  // open file
  auto fileHandle = fopen(argv[1], "rb");
  if (!fileHandle) {
    fprintf(stderr, "%s not found.\n", argv[1]);
    exit(1);
  }

  // find file length
  fseek(fileHandle, 0, SEEK_END);
  int fileLength = (int)ftell(fileHandle);
  fseek(fileHandle, 0, SEEK_SET);

  // allocated buffer
  auto buffer = malloc(fileLength);
  if (!buffer) {
    fprintf(stderr, "malloc failed.\n");
    fclose(fileHandle);
    exit(1);
  }

  // read file into buffer
  if (fread(buffer, fileLength, 1, fileHandle) != 1) {
    fprintf(stderr, "fread failed.\n");
    fclose(fileHandle);
    free(buffer);
    exit(1);
  }
  fclose(fileHandle);

  // run fuzzer
  int nRet = LLVMFuzzerTestOneInput(buffer, fileLength);

  // clean up
  free(buffer);

  return nRet;
}
