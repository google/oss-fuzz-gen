#include "json.h"
#include "test.h"

int main(void)
{
	// Empty
	TEST_EQUAL(json::jtype::detect(""), json::jtype::not_valid);

	// Stirng
	TEST_EQUAL(json::jtype::detect(" \"test string\""), json::jtype::jstring);

	// Number
	TEST_EQUAL(json::jtype::detect(" 123"), json::jtype::jnumber);
	TEST_EQUAL(json::jtype::detect(" -123"), json::jtype::jnumber);

	// Object
	TEST_EQUAL(json::jtype::detect(" {\"hello\":\"world\""), json::jtype::jobject);

	// Array
	TEST_EQUAL(json::jtype::detect(" [1,2,3]"), json::jtype::jarray);

	// Bool
	TEST_EQUAL(json::jtype::detect(" true"), json::jtype::jbool);
	TEST_EQUAL(json::jtype::detect(" false"), json::jtype::jbool);

	// Null
	TEST_EQUAL(json::jtype::detect(" null"), json::jtype::jnull);

	// Invalid
	TEST_EQUAL(json::jtype::detect(" abc"), json::jtype::not_valid);
}