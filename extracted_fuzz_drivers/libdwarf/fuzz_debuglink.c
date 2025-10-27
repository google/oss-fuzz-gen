/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <fcntl.h> /* open() O_RDONLY O_BINARY */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Libdwarf library callers can only use these headers.
 */
#include "dwarf.h"
#include "libdwarf.h"
#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Fuzzer function targeting a case of dwarf_gnu_debuglink
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  int fuzz_fd = 0;
  Dwarf_Ptr errarg = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Error *errp = NULL;
  Dwarf_Debug dbg = 0;

  fuzz_fd = open(filename, O_RDONLY | O_BINARY);
  if (fuzz_fd != -1) {
    dwarf_init_b(fuzz_fd, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, errp);

    int res = 0;
    char *debuglink_path = 0;
    unsigned char *crc = 0;
    char *debuglink_fullpath = 0;
    unsigned debuglink_fullpath_strlen = 0;
    unsigned buildid_type = 0;
    char *buildidowner_name = 0;
    unsigned char *buildid_itself = 0;
    unsigned buildid_length = 0;
    char **paths = 0;
    unsigned paths_count = 0;
    unsigned i = 0;

    /*  This is just an example if one knows
        of another place full-DWARF objects
        may be. "/usr/lib/debug" is automatically
        set. */
    res = dwarf_add_debuglink_global_path(dbg, "/usr/include/c++/9/debug", errp);
    res = dwarf_gnu_debuglink(dbg, &debuglink_path, &crc, &debuglink_fullpath, &debuglink_fullpath_strlen, &buildid_type, &buildidowner_name, &buildid_itself, &buildid_length, &paths, &paths_count, errp);
    /*  Calling dwarf_gnu_debuglink and passing in
        &paths here means the caller
        is obligated to free the array/block of strings
        returned. dwarf_finish() will NOT
        free these strings. See the libdwarf documentation.  */
    free(paths);
    /*  Calling dwarf_gnu_debuglink and passing in
        &debuglink_fullpath  means the caller
        is obligated to free the array/block of strings
        returned. dwarf_finish() will NOT
        free these strings. See the libdwarf documentation.  */
    free(debuglink_fullpath);

    dwarf_finish(dbg);
    close(fuzz_fd);
  }

  unlink(filename);
  return 0;
}
