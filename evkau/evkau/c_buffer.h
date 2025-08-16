#pragma once

#include "_globaldef.h"
#include <vector>

// Buffer type aliases implemented with std::vector. The former c_buffer
// template has been removed in favour of direct std::vector usage.
typedef std::vector<unsigned char> c_byte_buffer;
typedef std::vector<int> c_int_buffer;
typedef std::vector<char> c_char_buffer;
typedef std::vector<std::string> c_string_buffer;
typedef std::vector<std::wstring> c_wstring_buffer;
