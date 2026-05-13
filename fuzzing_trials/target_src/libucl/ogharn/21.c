#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_21(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        
   enum ucl_duplicate_strategy UCL_DUPLICATE_MERGEVAL = UCL_DUPLICATE_MERGE;
   enum ucl_parse_type UCL_PARSE_UCLVAL = UCL_PARSE_UCL;

   struct ucl_parser* ucl_parser_newval1 = ucl_parser_new(-1);
	if(!ucl_parser_newval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_parser_add_string_priorityval1 = ucl_parser_add_string_priority(ucl_parser_newval1, fuzzData, size, 0);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_add_string_priorityval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_parser_add_chunk_fullval1 = ucl_parser_add_chunk_full(ucl_parser_newval1, fuzzData, size, -1, UCL_DUPLICATE_MERGEVAL, UCL_PARSE_UCLVAL);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_add_chunk_fullval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
