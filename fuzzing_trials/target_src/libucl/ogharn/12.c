#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_12(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        
   enum ucl_duplicate_strategy UCL_DUPLICATE_REWRITEVAL = UCL_DUPLICATE_REWRITE;
   enum ucl_parse_type UCL_PARSE_AUTOVAL = UCL_PARSE_AUTO;

   struct ucl_parser* ucl_parser_newval1 = ucl_parser_new(0);
	if(!ucl_parser_newval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_parser_add_chunk_fullval1 = ucl_parser_add_chunk_full(ucl_parser_newval1, fuzzData, size, 64, UCL_DUPLICATE_REWRITEVAL, UCL_PARSE_AUTOVAL);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_add_chunk_fullval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_parser_set_filevarsval1 = ucl_parser_set_filevars(ucl_parser_newval1, NULL, ucl_parser_add_chunk_fullval1);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_set_filevarsval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
