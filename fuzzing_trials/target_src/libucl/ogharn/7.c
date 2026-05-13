#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_7(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        
   enum ucl_duplicate_strategy UCL_DUPLICATE_MERGEVAL = UCL_DUPLICATE_MERGE;
   enum ucl_parse_type UCL_PARSE_UCLVAL = UCL_PARSE_UCL;

   double ucl_object_fromdoublevar0 = 2.0;
   ucl_object_iter_t ucl_object_iterate_with_errorvar0;
	memset(&ucl_object_iterate_with_errorvar0, 0, (sizeof ucl_object_iterate_with_errorvar0));

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
   ucl_object_t* ucl_object_fromdoubleval1 = ucl_object_fromdouble(ucl_object_fromdoublevar0);
	if(!ucl_object_fromdoubleval1){
		fprintf(stderr, "err");
		exit(0);	}
   ucl_object_t* ucl_object_iterate_with_errorval1 = ucl_object_iterate_with_error(ucl_object_fromdoubleval1, &ucl_object_iterate_with_errorvar0, ucl_parser_add_chunk_priorityval1, 64);
	if(!ucl_object_iterate_with_errorval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_parser_add_fd_fullval1 = ucl_parser_add_fd_full(ucl_parser_newval1, 4, 64, UCL_DUPLICATE_MERGEVAL, UCL_PARSE_UCLVAL);
	if(ucl_parser_add_fd_fullval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
