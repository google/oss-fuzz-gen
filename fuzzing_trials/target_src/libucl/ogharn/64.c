#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_64(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        

   ucl_object_t ucl_object_mergevar0;
	memset(&ucl_object_mergevar0, 0, (sizeof ucl_object_mergevar0));

   ucl_object_t ucl_object_mergevar1;
	memset(&ucl_object_mergevar1, 0, (sizeof ucl_object_mergevar1));

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
   bool ucl_object_mergeval1 = ucl_object_merge(&ucl_object_mergevar0, &ucl_object_mergevar1, ucl_parser_add_chunk_priorityval1);
	if(ucl_object_mergeval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_array_prependval1 = ucl_array_prepend(&ucl_object_mergevar0, &ucl_object_mergevar0);
	if(ucl_array_prependval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   unsigned int ucl_array_index_ofval1 = ucl_array_index_of(&ucl_object_mergevar0, &ucl_object_mergevar0);
	if(ucl_array_index_ofval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
