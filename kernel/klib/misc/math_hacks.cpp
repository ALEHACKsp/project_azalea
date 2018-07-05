#include "math_hacks.h"

// Round a number to the next-highest power of two.
uint64_t round_to_power_two(uint64_t input)
{
  uint64_t pos;
  uint64_t output;
  uint64_t first_in = input;

  if (input == 0)
  {
    return 0;
  }

  if ((input & 0x1000000000000000) != 0)
  {
    return 0;
  }

  pos = __builtin_clzl(input);
  output = (uint64_t)1 << (63 - pos);

  if (first_in != output)
  {
    output = output << 1;
  }

  return output;
}
