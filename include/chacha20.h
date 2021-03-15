#include <vector>
#include <string>
#include <sstream>
#include <iostream>

uint32_t string_to_uint32(std::string word_in_string)
{
  return static_cast<uint32_t>(std::stoul(word_in_string));
}
std::string uint32_to_string(uint32_t word)
{
  return std::to_string(word);
}

std::vector<uint32_t> translate_strings(std::vector<std::string> strings)
{
  std::vector<uint32_t> words;
  for (auto element : strings)
    words.push_back(string_to_uint32(element));
  return words;
}

std::vector<std::string> translate_words(std::vector<uint32_t> words)
{
  std::vector<std::string> strings;
  for (auto element : words)
    strings.push_back(uint32_to_string(element));
  return strings;
}

std::string uint32_to_hexstr(uint32_t word)
{
  std::stringstream result;
  result << std::hex << word;
  return result.str();
}

std::vector<std::string> hex_strings(std::vector<uint32_t> words)
{
  std::vector<std::string> result;
  for (auto element : words)
    result.push_back(uint32_to_hexstr(element));
  return result;
}

std::string words_to_string(std::vector<uint32_t> words)
{
  std::string output = "[\n";
  int i = 0;
  for (auto word : words)
  {
    output += uint32_to_string(word) + ", ";
    if ((i % 4) == 0)
    {
      output += "\n";
    }
    i++;
  }
  output += "]\n";
  return output;
}

std::string strings_to_string(std::vector<std::string> words)
{
  std::string output = "[\n";
  int i = 0;
  for (auto word : words)
  {
    output += word + ", ";

    i++;
    if ((i % 4) == 0)
    {
      output += "\n";
    }
  }
  output += "]\n";
  return output;
}