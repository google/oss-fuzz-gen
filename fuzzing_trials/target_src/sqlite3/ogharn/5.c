#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_5(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   int sqlite3_table_column_metadatavarINTsize = sizeof(NULL);
   int sqlite3_os_initval1 = sqlite3_os_init();
   int sqlite3_openval1 = sqlite3_open(":memory:", &sqlite3_openvar1);
	if((int)sqlite3_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_table_column_metadataval1 = sqlite3_table_column_metadata(sqlite3_openvar1, NULL, fuzzData, fuzzData, &fuzzData, NULL, &sqlite3_table_column_metadatavarINTsize, &sqlite3_openval1, NULL);
	if((int)sqlite3_table_column_metadataval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_drop_modulesval1 = sqlite3_drop_modules(sqlite3_openvar1, &fuzzData);
	if((int)sqlite3_drop_modulesval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
