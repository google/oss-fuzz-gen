#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_10(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        

   size_t ucl_object_reservevar0 = 64;
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
   bool ucl_parser_insert_chunkval1 = ucl_parser_insert_chunk(ucl_parser_newval1, fuzzData, size);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_insert_chunkval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   ucl_object_t* ucl_parser_get_commentsval1 = ucl_parser_get_comments(ucl_parser_newval1);
	if(!ucl_parser_get_commentsval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_object_reserveval1 = ucl_object_reserve(ucl_parser_get_commentsval1, ucl_object_reservevar0);
	if(ucl_object_reserveval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
