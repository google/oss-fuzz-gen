#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_18(char *fuzzData, size_t size)
{
  char *fuzzDataCmp = fuzzData;

	
        

   size_t ucl_object_insert_keyvar0 = 64;
   size_t ucl_object_delete_keylvar0 = 64;
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
   ucl_object_t* ucl_object_newval1 = ucl_object_new();
	if(!ucl_object_newval1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_object_insert_keyval1 = ucl_object_insert_key(ucl_object_newval1, ucl_object_newval1, fuzzData, ucl_object_insert_keyvar0, ucl_parser_add_chunk_priorityval1);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_object_insert_keyval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   bool ucl_object_delete_keylval1 = ucl_object_delete_keyl(ucl_object_newval1, fuzzData, ucl_object_delete_keylvar0);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_object_delete_keylval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   int ucl_object_compare_qsortval1 = ucl_object_compare_qsort(&ucl_object_newval1, &ucl_object_newval1);
	if(ucl_object_compare_qsortval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
