#include "json.h"
#include "test.h"

int main(void)
{
	// Test parsing
	const char *test_string = " \t \n \v \f \r abc123";
	TEST_STRING_EQUAL(json::parsing::tlws(test_string), "abc123");
	json::parsing::tlws(test_string);
	TEST_STRING_EQUAL(json::parsing::tlws(test_string), "abc123");
	test_string = " \t \n \v \f \r";
	TEST_STRING_EQUAL(json::parsing::tlws(test_string), "");
}