#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_52(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        
   enum ucl_duplicate_strategy UCL_DUPLICATE_APPENDVAL = UCL_DUPLICATE_APPEND;
   enum ucl_parse_type UCL_PARSE_UCLVAL = UCL_PARSE_UCL;

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
   bool ucl_parser_add_chunk_fullval1 = ucl_parser_add_chunk_full(ucl_parser_newval1, fuzzData, size, -1, UCL_DUPLICATE_APPENDVAL, UCL_PARSE_UCLVAL);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_add_chunk_fullval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   ucl_object_t* ucl_object_fromstringval1 = ucl_object_fromstring(fuzzData);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(!ucl_object_fromstringval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_object_reserveval1 = ucl_object_reserve(ucl_object_fromstringval1, ucl_object_reservevar0);
	if(ucl_object_reserveval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
