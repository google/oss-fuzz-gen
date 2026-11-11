#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <tree_data.h>
#include <libyang.h>
#include <parser_schema.h>
#include <context.h>
#include <parser_data.h>

int LLVMFuzzerTestOneInput_1(char *fuzzData, size_t size)
{
	

   LY_ERR ly_pattern_matchval1 = ly_pattern_match(NULL, fuzzData, fuzzData, size, NULL);
   return 0;
}
