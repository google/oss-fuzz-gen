#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_2(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        

   struct ucl_parser* ucl_parser_newval1 = ucl_parser_new(0);
	if(!ucl_parser_newval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_parser_add_stringval1 = ucl_parser_add_string(ucl_parser_newval1, fuzzData, size);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_add_stringval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_parser_add_chunk_priorityval1 = ucl_parser_add_chunk_priority(ucl_parser_newval1, fuzzData, size, -1);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_add_chunk_priorityval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
