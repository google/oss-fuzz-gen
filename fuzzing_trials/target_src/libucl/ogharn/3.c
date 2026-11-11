#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_3(char *fuzzData, size_t size)
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
   ucl_object_t* ucl_parser_get_current_stack_objectval1 = ucl_parser_get_current_stack_object(ucl_parser_newval1, 0);
	if(!ucl_parser_get_current_stack_objectval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_object_mergeval1 = ucl_object_merge(ucl_parser_get_current_stack_objectval1, ucl_parser_get_current_stack_objectval1, ucl_parser_add_chunk_priorityval1);
	if(ucl_object_mergeval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
