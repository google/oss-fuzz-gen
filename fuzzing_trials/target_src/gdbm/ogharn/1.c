#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <gdbm.h>
#include <gdbmtool.h>

int LLVMFuzzerTestOneInput_1(char *fuzzData, size_t size)
{
	

   GDBM_FILE gdbm_open_extval1 = gdbm_open_ext(fuzzData, GDBM_META_MASK_OWNER, NULL);
   return 0;
}
