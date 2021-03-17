#include "../include/Catch2/catch.h"
#include "../include/chacha20.h"

SCENARIO("ChaCha20 Ciphering - UINT32 and STRING convert")
{
  GIVEN("A string hexadecimal word in UINT32 value")
  {
    WHEN("conversion to UINT32 is applied")
    {
      uint32_t expected_value = string_to_uint32("61707865");

      THEN("an unsigned int of 32b is returned")
      {
        REQUIRE(expected_value == 1634760805);
      }
    }
    AND_WHEN("conversion to string is applied")
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
              "1634760805, 857760878, 2036477234, 1797285236, \n"
              "66051, 67438087, 134810123, 202182159, \n"
              "269554195, 336926231, 404298267, 471670303, \n"
              "16777216, 9, 74, 0, \n"
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
              "61707865, 3320646e, 79622d32, 6b206574, \n"
              "10203, 4050607, 8090a0b, c0d0e0f, \n"
              "10111213, 14151617, 18191a1b, 1c1d1e1f, \n"
              "1000000, 9, 4a, 0, \n"
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
        for (int i = BASE; i < inverted_strings_v.size(); i++)
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
        REQUIRE(result == 3269521610);
      }
    }
  }
}

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
          // 32b ctr and 96b nonce
          "01000000", "00000009", "0000004a", "00000000"};
      std::vector<std::string> result_v;
      strings_v = reverse_set(strings_v, BASE, OFFSET);
      result_v = chacha_block(result_v, strings_v, ROUNDS, false);
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

SCENARIO("ChaCha20 Ciphering - Testing the given key and nonce in class (17/03/2021)")
{
  GIVEN("A set of strings with words, key, counter and nonce")
  {
    WHEN("Applied chacha block for 20 rounds to inverted set")
    {

      std::vector<std::string> strings_v = {
          //128b Word
          "61707865", "3320646e", "79622d32", "6b206574",
          // 256b Key
          "0e99a397", "3c53eb1b", "e2426bad", "2f312d24",
          "d9c2762b", "535e14d7", "8e1775a9", "453a68a5",
          //32b Counter and 96b nonce
          "01000000", "b69edeac", "73ee4405", "d3fa9a8e"};
      std::vector<std::string> result_v;
      strings_v = reverse_set(strings_v, BASE, OFFSET);
      result_v = chacha_block(result_v, strings_v, ROUNDS, false);
      THEN("output is the cipherer set")
      {
        REQUIRE(strings_to_string(result_v) ==
                "[\n"
                "935d7845, f168dee7, 4820e00a, 5477c538, \n"
                "ddbf5c71, 71a53ccd, 5738f9ba, 828b8df5, \n"
                "850f8ea, deb5cb25, 9bb56dd0, aca7cb38, \n"
                "95a77f35, 1f92c09, c8d3851b, 42c97c15, \n"
                "]\n");
      }
    }
  }
}