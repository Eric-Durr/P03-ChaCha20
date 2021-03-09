/**
 * 
 * Author: Eric Dürr Sierra | eric.durr.20@ull.edu.es
 * 
 * Created: 01/03/2021
 * Modified: 01/03/2021
 * 
 * 
 */

#include "../include/Catch2/catch.h"
#include "../include/rc4_functions.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <string_view>

SCENARIO("Testing the RC4 generator")
{
  std::vector<int> original = {1, 34};
  std::vector<int> ciphered;
  ciphered.resize(original.size());
  GIVEN("A seed")
  {
    std::vector<int> seed = {1, 35, 69, 103, 137, 171, 205, 239}, s;
    WHEN("The initialization creates s and k")
    {
      initializeRC4(s, seed);
      THEN("s elements must be swapped in any order")
      {
        std::vector<int> ordered;
        for (int i = 0; i < 256; i++)
        {
          ordered.push_back(i);
        }
        REQUIRE(s != ordered);
        std::cout << "seed: " << secuenceToString(seed) << "\n";
        std::cout << "s: " << secuenceToString(s) << "\n";
        ciphered = generateCipheringSecuence(original, s);
        std::cout << "original: " << secuenceToString(original) << "\n";
        std::cout << "ciphered: " << secuenceToString(ciphered) << "\n";
        REQUIRE(ciphered[0] == 145);
        REQUIRE(ciphered[1] == 44);
      }
    }
  }
}