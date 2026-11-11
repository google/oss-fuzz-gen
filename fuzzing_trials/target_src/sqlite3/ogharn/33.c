#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_33(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   char* sqlite3_table_column_metadatavar1[256];
	sprintf(sqlite3_table_column_metadatavar1, "/tmp/pdp6r");
   char** sqlite3_table_column_metadatavar5[256];
	sprintf(sqlite3_table_column_metadatavar5, "/tmp/65ee4");
   int sqlite3_table_column_metadatavarINTsize = sizeof(sqlite3_table_column_metadatavar5);
   void* sqlite3_execvar3[256];
	sprintf(sqlite3_execvar3, "/tmp/7o8h3");
   char** sqlite3_execvar4[256];
	sprintf(sqlite3_execvar4, "/tmp/0thy3");
   int sqlite3_get_tablevarINTsize = sizeof(sqlite3_table_column_metadatavar5);
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
   int sqlite3_get_tableval1 = sqlite3_get_table(sqlite3_openvar1, fuzzData, &sqlite3_table_column_metadatavar5, &sqlite3_get_tablevarINTsize, &sqlite3_execval1, &fuzzData);
	if((int)sqlite3_get_tableval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_table_column_metadatavar5){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
