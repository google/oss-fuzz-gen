#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_28(char *fuzzData, size_t size)
{
	
        
   icalcomponent_kind ICAL_ANY_COMPONENTVAL = ICAL_ANY_COMPONENT;

   struct icaltimetype icalcomponent_set_recurrenceidvar0;
	memset(&icalcomponent_set_recurrenceidvar0, 0, (sizeof icalcomponent_set_recurrenceidvar0));

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_new_from_stringval1);
   icalcomponent_set_recurrenceid(icalcomponent_new_from_stringval1, icalcomponent_set_recurrenceidvar0);
   icalcompiter icalcomponent_begin_componentval1 = icalcomponent_begin_component(icalcomponent_new_from_stringval1, ICAL_ANY_COMPONENTVAL);
   return 0;
}
