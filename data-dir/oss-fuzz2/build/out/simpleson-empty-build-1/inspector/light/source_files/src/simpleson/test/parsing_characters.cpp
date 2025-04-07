#include "json.h"
#include "test.h"
#include <string>

int main(void)
{
	const char *input = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result = json::parsing::encode_string(input);
    const char *expected_result = "\"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\"";
    TEST_STRING_EQUAL(result.c_str(), expected_result);
    std::string echo = json::parsing::decode_string(result.c_str());
    TEST_STRING_EQUAL(echo.c_str(), input);

    input = "\" \\ / \b \f \n \r \t";
    result = json::parsing::encode_string(input);
    expected_result = "\"\\\" \\\\ \\/ \\b \\f \\n \\r \\t\"";
    TEST_STRING_EQUAL(result.c_str(), expected_result);
    echo = json::parsing::decode_string(result.c_str());
    TEST_STRING_EQUAL(echo.c_str(), input);
}