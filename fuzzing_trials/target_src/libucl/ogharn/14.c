#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

static void ucl_userdata_dtorfp(void *ud){
exit(0);
}
static const ucl_userdata_emitterfp(void *ud){
exit(0);
}
int LLVMFuzzerTestOneInput_14(char *fuzzData, size_t size)
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
   bool ucl_parser_insert_chunkval1 = ucl_parser_insert_chunk(ucl_parser_newval1, fuzzData, size);
	if(strcmp(fuzzDataCmp, fuzzData)){
		fprintf(stderr, "err");
		exit(0);	}
	if(ucl_parser_insert_chunkval1 < 1){
		fprintf(stderr, "err");
		exit(0);	}
   ucl_object_t* ucl_object_new_userdataval1 = ucl_object_new_userdata(ucl_userdata_dtorfp, ucl_userdata_emitterfp, (void*)ucl_parser_newval1);
	if(!ucl_object_new_userdataval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* ucl_copy_value_trashval1 = ucl_copy_value_trash(ucl_object_new_userdataval1);
	if(!ucl_copy_value_trashval1){
		fprintf(stderr, "err");
		exit(0);	}
   ucl_object_t* ucl_object_copyval1 = ucl_object_copy(ucl_object_new_userdataval1);
	if(!ucl_object_copyval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
