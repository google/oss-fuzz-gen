#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_112(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   char* sqlite3_table_column_metadatavar1[256];
	sprintf(sqlite3_table_column_metadatavar1, "/tmp/64wnw");
   char** sqlite3_table_column_metadatavar5[256];
	sprintf(sqlite3_table_column_metadatavar5, "/tmp/akuoy");
   int sqlite3_table_column_metadatavarINTsize = sizeof(sqlite3_table_column_metadatavar5);
   void* sqlite3_execvar3[256];
	sprintf(sqlite3_execvar3, "/tmp/6r8q8");
   char** sqlite3_execvar4[256];
	sprintf(sqlite3_execvar4, "/tmp/6bxyl");
   sqlite3_uint64 sqlite3_result_text64var2;
	memset(&sqlite3_result_text64var2, 0, sizeof(sqlite3_result_text64var2));

   int sqlite3_os_initval1 = sqlite3_os_init();
   int sqlite3_openval1 = sqlite3_open(":memory:", &sqlite3_openvar1);
	if((int)sqlite3_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_table_column_metadataval1 = sqlite3_table_column_metadata(sqlite3_openvar1, sqlite3_table_column_metadatavar1, fuzzData, NULL, NULL, sqlite3_table_column_metadatavar5, &sqlite3_table_column_metadatavarINTsize, NULL, &sqlite3_os_initval1);
	if((int)sqlite3_table_column_metadataval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_execval1 = sqlite3_exec(sqlite3_openvar1, fuzzData, NULL, sqlite3_execvar3, sqlite3_execvar4);
	if((int)sqlite3_execval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_execvar4){
		fprintf(stderr, "err");
		exit(0);	}
   sqlite3_result_text64(NULL, *sqlite3_execvar4, sqlite3_result_text64var2, NULL, *fuzzData);
   return 0;
}
