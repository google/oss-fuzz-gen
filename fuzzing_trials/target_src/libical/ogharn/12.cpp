#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_12(char *fuzzData, size_t size)
{
	
        

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_new_from_stringval1);
   struct icaldurationtype icalcomponent_get_durationval1 = icalcomponent_get_duration(icalcomponent_new_from_stringval1);
   int icalcomponent_get_sequenceval1 = icalcomponent_get_sequence(icalcomponent_new_from_stringval1);
	if(icalcomponent_get_sequenceval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
