#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

static void function_pointer3458764546337931264fp(sqlite3_context*, int, sqlite3_value**){
	exit(0);
}
int LLVMFuzzerTestOneInput_55(char *fuzzData, size_t size)
{
	

   sqlite3* sqlite3_openvar1;
	memset(&sqlite3_openvar1, 0, sizeof(sqlite3_openvar1));

   char*** sqlite3_get_tablevar2[256];
	sprintf(sqlite3_get_tablevar2, "/tmp/14wgq");
   int sqlite3_get_tablevarINTsize = sizeof(sqlite3_get_tablevar2);
   int sqlite3_os_initval1 = sqlite3_os_init();
   int sqlite3_openval1 = sqlite3_open(":memory:", &sqlite3_openvar1);
	if((int)sqlite3_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_openvar1){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_get_tableval1 = sqlite3_get_table(sqlite3_openvar1, fuzzData, sqlite3_get_tablevar2, &sqlite3_get_tablevarINTsize, &sqlite3_os_initval1, &fuzzData);
	if((int)sqlite3_get_tableval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!sqlite3_get_tablevar2){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_drop_modulesval1 = sqlite3_drop_modules(sqlite3_openvar1, *sqlite3_get_tablevar2);
	if((int)sqlite3_drop_modulesval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int sqlite3_create_functionval1 = sqlite3_create_function(sqlite3_openvar1, sqlite3_get_tablevar2, sqlite3_os_initval1, sqlite3_get_tableval1, (void*)sqlite3_openvar1, function_pointer3458764546337931264fp, NULL, NULL);
	if((int)sqlite3_create_functionval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
