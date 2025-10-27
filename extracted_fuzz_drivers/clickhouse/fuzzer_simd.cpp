#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

#include "libdivide.h"

#if __cplusplus < 201703L
#error "Sorry, needs C++17 or later."
#endif

// How many bytes of data to use for numerators at most.
// Must be larger than the largest simd size.
constexpr const std::size_t NbytesOfInput = 512 / 8;

// how much data to consume for the divisor (at most).
constexpr const std::size_t NbytesForDivisor = sizeof(std::int64_t);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // pick what types to operate on from the fuzz data
  if (Size < 2)
    return 0;
  const auto type_selector = Data[0];
  const auto branchfree_selector = Data[1];
  Data += 2;
  Size -= 2;

  // exit early to avoid reading outside bounds later
  if (Size < NbytesOfInput + NbytesForDivisor) {
    return 0;
  }

  // This generic lambda does the work for us, by conveniently deducing the type
  // It will return an int, just so the switch case looks prettier at the
  // call site.
  auto outer = [&](const auto integerdummy) -> int {
    auto inner = [&](const auto branchingtypedummy) -> int {
      using Integer = std::remove_const_t<decltype(integerdummy)>;
      static_assert(std::is_integral_v<Integer>, "input should be an integer");

      // pick the divisor from the fuzz data
      const Integer divisor = [&]() {
        static_assert(sizeof(Integer) <= NbytesForDivisor, "make NbytesForDivisor larger");
        Integer tmp;
        std::memcpy(&tmp, Data, sizeof(Integer));
        Data += NbytesForDivisor;
        Size -= NbytesForDivisor;
        return tmp;
      }();

      // don't let the universe explode
      if (divisor == 0) {
        return 0;
      }

      // respect the branchfree variant prohibiting 1
      if (branchingtypedummy.value == libdivide::BRANCHFREE && divisor == 1) {
        return 0;
      }

      // This array type is used for both input and output. It may be overly
      // large for the smaller simd types.
      using ArrayOfIntegers = std::array<Integer, NbytesOfInput / sizeof(Integer)>;

      // The numbers to later divide by divisor
      ArrayOfIntegers numerators;
      numerators.fill(0);
      if (Size < NbytesOfInput)
        return 0;
      std::memcpy(numerators.data(), Data, NbytesOfInput);

      // avoid problems with integer overflow from INT_MIN/-1
      if (std::is_signed_v<Integer> && divisor == -1) {
        for (auto &e : numerators) {
          if (e == std::numeric_limits<Integer>::min()) {
            e = 0;
          }
        }
      }

      // get data into a simd register
#if defined(LIBDIVIDE_AVX512)
      // not tested!
      using Vector = __m512i;
      const Vector num_as_simdvector = _mm512_loadu_si512((const Vector *)numerators.data());
#endif

#if defined(LIBDIVIDE_AVX2)
      using Vector = __m256i;
      const Vector num_as_simdvector = _mm256_loadu_si256((const Vector *)numerators.data());
#endif

#if defined(LIBDIVIDE_SSE2)
      using Vector = __m128i;
      const Vector num_as_simdvector = _mm_loadu_si128((const Vector *)numerators.data());
#endif
      // carry out the division
      libdivide::divider<Integer, branchingtypedummy.value> divider(divisor);
      const Vector res = num_as_simdvector / divider;

      // this will eventually contain the result
      ArrayOfIntegers simdresult;
      simdresult.fill(0);

      // copy the results from the simd register
#if defined(LIBDIVIDE_AVX512)
      _mm512_storeu_si512((Vector *)simdresult.data(), res);
#endif

#if defined(LIBDIVIDE_AVX2)
      _mm256_storeu_si256((Vector *)simdresult.data(), res);
#endif

#if defined(LIBDIVIDE_SSE2)
      _mm_storeu_si128((Vector *)simdresult.data(), res);
#endif

      // how many elements will be assigned?
      constexpr const std::size_t Nelements = sizeof(Vector) / sizeof(Integer);

      // validate the result
      for (std::size_t i = 0; i < Nelements; ++i) {
        const Integer expected = numerators.at(i) / divisor;
        const Integer actual = simdresult.at(i);
        if (expected != actual)
          abort();
      }
      return 0;
    };

    if (branchfree_selector == libdivide::BRANCHFULL) {
      return inner(std::integral_constant<int, libdivide::BRANCHFULL>{});
    } else if (branchfree_selector == libdivide::BRANCHFREE) {
      return inner(std::integral_constant<int, libdivide::BRANCHFREE>{});
    }
    return 0;
  };

  switch (type_selector) {
  case 0:
    return outer(std::uint32_t{});
  case 1:
    return outer(std::int32_t{});
  case 2:
    return outer(std::uint64_t{});
  case 3:
    return outer(std::int64_t{});
  default:
    return 0;
  }
  return 0;
}
