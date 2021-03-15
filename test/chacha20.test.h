#include "../include/Catch2/catch.h"
#include "../include/chacha20.h"

SCENARIO("ChaCha20 Ciphering -  UINT32 & STRING convert")
{
  GIVEN("A string hexadecimal word")
  {
    WHEN("conversion to UINT32 is applied")
    {
      uint32_t expected_value = string_to_uint32("61707865");

      THEN("an unsigned int of 32b is returned")
      {
        REQUIRE(expected_value == 61707865);
      }
    }
    AND_WHEN("conversion to UINT32 is applied")
    {
      std::string expected_value = uint32_to_string(61707865);

      THEN("an unsigned int of 32b is returned")
      {
        REQUIRE(expected_value == "61707865");
      }
    }
  }

  GIVEN("A vector of strings")
  {
    std::vector<std::string> origin = {
        // 128b word
        "61707865", "3320646e", "79622d32", "6b206574",
        // 256b key
        "00010203", "04050607", "08090a0b", "0c0d0e0f",
        "10111213", "14151617", "18191a1b", "1c1d1e1f",
        // 32b ctr + 96b nonce
        "01000000", "00000009", "0000004a", "00000000"};

    WHEN("conversion to all the string elements is aplied")
    {
      std::vector<uint32_t> uint32_result = translate_strings(origin);
      THEN("A vector of UINT32 values is returned")
      {
        for (auto i = 0; i < uint32_result.size(); i++)
        {
          REQUIRE(uint32_result[i] == string_to_uint32(origin[i]));
        }
      }
    }
  }
  GIVEN("A vector of uint32 elements")
  {
    std::vector<std::string> expected = {
        // 128b word
        "61707865", "3320646e", "79622d32", "6b206574",
        // 256b key
        "00010203", "04050607", "08090a0b", "0c0d0e0f",
        "10111213", "14151617", "18191a1b", "1c1d1e1f",
        // 32b ctr + 96b nonce
        "01000000", "00000009", "0000004a", "00000000"};
    std::vector<uint32_t> origin = translate_strings(expected);

    WHEN("conversion to all the uint32 elements is aplied")
    {
      expected = translate_words(origin);
      THEN("A vector of UINT32 values is returned")
      {
        for (auto i = 0; i < expected.size(); i++)
        {
          REQUIRE(expected[i] == uint32_to_string(origin[i]));
        }
      }
    }
  }
}

SCENARIO("ChaCha20 Ciphering - UINT32 to HEX_STRING convert ")
{
  GIVEN("A vector of UINT32 words")
  {
    std::vector<std::string> strings_v = {
        // 128b word
        "61707865", "3320646e", "79622d32", "6b206574",
        // 256b key
        "00010203", "04050607", "08090a0b", "0c0d0e0f",
        "10111213", "14151617", "18191a1b", "1c1d1e1f",
        // 32b ctr + 96b nonce
        "01000000", "00000009", "0000004a", "00000000"};
    std::vector<uint32_t> uint32_v = translate_strings(strings_v);
    WHEN("Conversion is applied")
    {
      std::vector<std::string> hexstr_v = hex_strings(uint32_v);
      THEN("A vector of Hexadecimal stringed  words is dropped")
      {
        for (int i = 0; i < hexstr_v.size(); i++)
        {
          REQUIRE(hexstr_v[i] == uint32_to_hexstr(uint32_v[i]));
        }
      }
    }
  }
}

SCENARIO("ChaCha20 ciphering - Conversion output")
{
  GIVEN("A vector of UINT32 words")
  {
    std::vector<std::string> strings_v = {
        // 128b word
        "61707865", "3320646e", "79622d32", "6b206574",
        // 256b key
        "00010203", "04050607", "08090a0b", "0c0d0e0f",
        "10111213", "14151617", "18191a1b", "1c1d1e1f",
        // 32b ctr + 96b nonce
        "01000000", "00000009", "0000004a", "00000000"};
    std::vector<uint32_t> uint32_v = translate_strings(strings_v);
    WHEN("Outputed as string")
    {
      THEN("Returns string with all elements formatted")
      {
        CHECK(words_to_string(uint32_v) == "");
      }
    }
  }

  GIVEN("A vector of UINT32 in string words")
  {
    std::vector<std::string> strings_v = {
        // 128b word
        "61707865", "3320646e", "79622d32", "6b206574",
        // 256b key
        "00010203", "04050607", "08090a0b", "0c0d0e0f",
        "10111213", "14151617", "18191a1b", "1c1d1e1f",
        // 32b ctr + 96b nonce
        "01000000", "00000009", "0000004a", "00000000"};
    WHEN("Outputed as string")
    {

      THEN("Returns string with all elements formatted")
      {
        CHECK(strings_to_string(strings_v) == "");
      }
    }
  }
  GIVEN("A vector of HEX STRING words")
  {
    std::vector<std::string> strings_v = {
        // 128b word
        "61707865", "3320646e", "79622d32", "6b206574",
        // 256b key
        "00010203", "04050607", "08090a0b", "0c0d0e0f",
        "10111213", "14151617", "18191a1b", "1c1d1e1f",
        // 32b ctr + 96b nonce
        "01000000", "00000009", "0000004a", "00000000"};
    std::vector<uint32_t> uint32_v = translate_strings(strings_v);
    std::vector<std::string> hexstr_v = hex_strings(uint32_v);
    WHEN("Outputed as string")
    {
      THEN("Returns string with all elements formatted")
      {
        CHECK(strings_to_string(hexstr_v) == "");
      }
    }
  }
}
