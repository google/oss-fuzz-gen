#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_32(char *fuzzData, size_t size)
{
	
        

   struct icaltimetype icalcomponent_set_recurrenceidvar0;
	memset(&icalcomponent_set_recurrenceidvar0, 0, (sizeof icalcomponent_set_recurrenceidvar0));

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_new_from_stringval1);
   icalcomponent_set_recurrenceid(icalcomponent_new_from_stringval1, icalcomponent_set_recurrenceidvar0);
   int icalproperty_recurrence_is_excludedval1 = icalproperty_recurrence_is_excluded(icalcomponent_new_from_stringval1, NULL, NULL);
	if(icalproperty_recurrence_is_excludedval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
