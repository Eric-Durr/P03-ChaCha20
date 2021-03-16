#include "../include/Catch2/catch.h"
#include "../include/chacha20.h"

/* 
SCENARIO("ChaCha20 Ciphering -  UINT32 and STRING convert")
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
        CHECK(words_to_string(uint32_v) ==
              "[\n"
              "61707865, 03320646, 00079622, 00000006, \n"
              "00010203, 04050607, 00008090, 00000000, \n"
              "10111213, 14151617, 00018191, 00000001, \n"
              "01000000, 00000009, 00000004, 00000000, \n"
              "]\n");
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
        CHECK(strings_to_string(strings_v) ==
              "[\n"
              "61707865, 3320646e, 79622d32, 6b206574, \n"
              "00010203, 04050607, 08090a0b, 0c0d0e0f, \n"
              "10111213, 14151617, 18191a1b, 1c1d1e1f, \n"
              "01000000, 00000009, 0000004a, 00000000, \n"
              "]\n");
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
        CHECK(strings_to_string(hexstr_v) ==
              "[\n"
              "3ad9659, 32ab46, 13706, 6, \n"
              "27db, 3dceaf, 1f9a, 0, \n"
              "9a48ed, d7efc1, 470f, 1, \n"
              "f4240, 9, 4, 0, \n"
              "]\n");
      }
    }
  }
}

SCENARIO("ChaCha20 Ciphering - Invert and rotate")
{
  GIVEN("A string values")
  {
    std::string test_value = "61707865";
    WHEN("Inverting a single string")
    {
      std::string inverted_value = reverse_string(test_value, OFFSET);
      std::string expected_value = "65787061";
      THEN("Returns the inverted string by two digits")
      {
        REQUIRE(inverted_value == expected_value);
      }
    }
    std::vector<std::string> strings_v = {
        // 128b word
        "61707865", "3320646e", "79622d32", "6b206574",
        // 256b key
        "00010203", "04050607", "08090a0b", "0c0d0e0f",
        "10111213", "14151617", "18191a1b", "1c1d1e1f",
        // 32b ctr + 96b nonce
        "01000000", "00000009", "0000004a", "00000000"};
    AND_WHEN("Inverting the key, counter and nonce from the set of strings")
    {
      std::vector<std::string> inverted_strings_v = reverse_set(strings_v, BASE, OFFSET);
      THEN("Returns all last 12 elements inverted")
      {
        for (int i = BASE - 1; i < inverted_strings_v.size(); i++)
        {
          CHECK(inverted_strings_v[i] == reverse_string(strings_v[i], OFFSET));
        }
      }
    }
  }
  GIVEN("UNIT32 word")
  {
    uint32_t test_value = string_to_uint32("61707865");
    WHEN("Applied rotation")
    {
      uint32_t result = ROTL(test_value, 1);
      THEN("Returns binary value rotated 1 cypher to left")
      {
        REQUIRE(123415730 == result);
      }
    }
  }
}
 */
SCENARIO("ChaCha20 Ciphering - QR (Quarter Round) and ChaCha Block")
{
  GIVEN("A set of strings with words, key, counter and nonce")
  {
    WHEN("Applied chacha block for 20 rounds to inverted set")
    {

      std::vector<std::string> strings_v = {
          // 128b word
          "61707865", "3320646e", "79622d32", "6b206574",
          // 256b key
          "00010203", "04050607", "08090a0b", "0c0d0e0f",
          "10111213", "14151617", "18191a1b", "1c1d1e1f",
          // 32b ctr + 96b nonce
          "01000000", "00000009", "0000004a", "00000000"};
      std::vector<std::string> result_v;
      strings_v = reverse_set(strings_v, BASE, OFFSET);
      result_v = chacha_block(result_v, strings_v, ROUNDS);
      THEN("output is the cipherer set")
      {
        REQUIRE(strings_to_string(result_v) ==
                "[\n"
                "e4e7f110, 15593bd1, 1fdd0f50, c47120a3, \n"
                "c7f4d1c7, 368c033, 9aaa2204, 4e6cd4c3, \n"
                "466482d2, 9aa9f07, 5d7c214, a2028bd9, \n"
                "d19c12b5, b94e16de, e883d0cb, 4e3c50a2, \n"
                "]\n");
      }
    }
  }
}
