#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_67(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        

   bool ucl_object_fromboolvar0 = true;
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
   ucl_object_t* ucl_object_fromboolval1 = ucl_object_frombool(ucl_object_fromboolvar0);
	if(!ucl_object_fromboolval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_object_toboolean_safeval1 = ucl_object_toboolean_safe(ucl_object_fromboolval1, &ucl_parser_add_chunk_priorityval1);
	if(ucl_object_toboolean_safeval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   int ucl_object_compareval1 = ucl_object_compare(ucl_object_fromboolval1, ucl_object_fromboolval1);
	if(ucl_object_compareval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
