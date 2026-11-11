#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_60(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        

   struct ucl_parser* ucl_parser_newval1 = ucl_parser_new(-1);
	if(!ucl_parser_newval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_parser_add_chunk_priorityval1 = ucl_parser_add_chunk_priority(ucl_parser_newval1, fuzzData, size, -1);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_add_chunk_priorityval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   ucl_object_t* ucl_object_fromintval1 = ucl_object_fromint(64);
	if(!ucl_object_fromintval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_set_include_pathval1 = ucl_set_include_path(ucl_parser_newval1, ucl_object_fromintval1);
	if(ucl_set_include_pathval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   double ucl_object_todoubleval1 = ucl_object_todouble(ucl_object_fromintval1);
   return 0;
}
