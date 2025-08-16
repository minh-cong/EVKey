#include <cassert>
#include <cwchar>
#include <string>
#include <vector>

// Minimal container type used by split_wstring
using c_wstring_buffer = std::vector<std::wstring>;

// Standalone implementation of split_wstring for testing purposes.
static void split_wstring(const wchar_t* str, const wchar_t token, c_wstring_buffer& ctn)
{
    std::wstring temp(str ? str : L"");
    std::wstring delimiter(1, token);
    wchar_t* context = nullptr;
    wchar_t* buffer = temp.empty() ? nullptr : &temp[0];
    wchar_t* pch = buffer ? wcstok(buffer, delimiter.c_str(), &context) : nullptr;
    while (pch != nullptr)
    {
        ctn.push_back(pch);
        pch = wcstok(nullptr, delimiter.c_str(), &context);
    }
}

int main()
{
    // Typical case
    {
        c_wstring_buffer tokens;
        split_wstring(L"one two three", L' ', tokens);
        assert(tokens.size() == 3);
        assert(tokens[0] == L"one");
        assert(tokens[1] == L"two");
        assert(tokens[2] == L"three");
    }

    // Leading and trailing delimiters
    {
        c_wstring_buffer tokens;
        split_wstring(L"  surrounded  ", L' ', tokens);
        assert(tokens.size() == 1);
        assert(tokens[0] == L"surrounded");
    }

    // Consecutive delimiters
    {
        c_wstring_buffer tokens;
        split_wstring(L"a,,b,,,c", L',', tokens);
        assert(tokens.size() == 3);
        assert(tokens[0] == L"a");
        assert(tokens[1] == L"b");
        assert(tokens[2] == L"c");
    }

    // Delimiter absent
    {
        c_wstring_buffer tokens;
        split_wstring(L"single", L' ', tokens);
        assert(tokens.size() == 1);
        assert(tokens[0] == L"single");
    }

    // Empty string
    {
        c_wstring_buffer tokens;
        split_wstring(L"", L',', tokens);
        assert(tokens.empty());
    }

    // String of only delimiters
    {
        c_wstring_buffer tokens;
        split_wstring(L",,,", L',', tokens);
        assert(tokens.empty());
    }

    return 0;
}
