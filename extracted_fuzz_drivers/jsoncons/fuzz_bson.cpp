#include <catch/catch.hpp>
#include <ctime>
#include <jsoncons/json.hpp>
#include <jsoncons_ext/bson/bson.hpp>
#include <limits>
#include <sstream>
#include <utility>
#include <vector>

using namespace jsoncons;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size) {
  std::string input(reinterpret_cast<const char *>(data), size);
  std::istringstream is(input);
  try {
    json j2 = bson::decode_bson<json>(is);
  } catch (const jsoncons::ser_error &) {
  }

  return 0;
}
