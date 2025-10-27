#include <cstdint>
#include <cstring>
#include <limits>

#include "libdivide.h"

constexpr const std::size_t Nmax = 8;

template <typename Integer> void applyOnScalars(const uint8_t *Data, size_t Size) {
  const auto N = sizeof(Integer);
  static_assert(N <= Nmax, "");
  if (Size < 2 * Nmax)
    return;

  Integer numerator, divisor;
  std::memcpy(&numerator, Data, N);
  Data += Nmax;
  std::memcpy(&divisor, Data, N);

  // avoid division by zero
  if (divisor == 0) {
    return;
  }

  // avoid signed integer overflow INT_MIN/-1
  if (std::is_signed_v<Integer> && (numerator == std::numeric_limits<Integer>::min() && divisor == -1)) {
    return;
  }

  libdivide::divider<Integer, libdivide::BRANCHFULL> fast_d_branchfull(divisor);
  const auto quotient_full = numerator / fast_d_branchfull;

  if (quotient_full != numerator / divisor) {
    abort();
  }

  if (divisor != 1) {
    libdivide::divider<Integer, libdivide::BRANCHFREE> fast_d_branchfree(divisor);

    const auto quotient_free = numerator / fast_d_branchfree;

    if (quotient_free != numerator / divisor) {
      abort();
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < Nmax)
    return 0;
  auto action = Data[0];
  ++Data;
  --Size;

  switch (action) {
  case 0: {
    applyOnScalars<std::int64_t>(Data, Size);
  } break;
  case 1: {
    applyOnScalars<std::int32_t>(Data, Size);
  } break;
  case 2: {
    applyOnScalars<std::uint64_t>(Data, Size);
  } break;
  case 3: {
    applyOnScalars<std::uint32_t>(Data, Size);
  } break;
  }
  return 0;
}
