#include "windows_support.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>
namespace npa {
namespace {
int length(std::size_t size) {
    if (size > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        throw std::length_error("Text too long");
    return static_cast<int>(size);
}
} // namespace
std::string utf8(const std::wstring &v) {
    if (v.empty())
        return {};
    // Windows can expose unpaired UTF-16 surrogates: flags=0 replaces them with U+FFFD.
    const auto n = WideCharToMultiByte(CP_UTF8, 0, v.data(), length(v.size()), nullptr, 0, nullptr, nullptr);
    if (n == 0)
        throw std::runtime_error("UTF-8 conversion failed");
    std::string out(static_cast<std::size_t>(n), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, v.data(), length(v.size()), out.data(), n, nullptr, nullptr) != n)
        throw std::runtime_error("UTF-8 conversion failed");
    return out;
}
std::wstring wide(const std::string &v) {
    if (v.empty())
        return {};
    const auto n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, v.data(), length(v.size()), nullptr, 0);
    if (n == 0)
        throw std::runtime_error("Invalid UTF-8");
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, v.data(), length(v.size()), out.data(), n) != n)
        throw std::runtime_error("UTF-16 conversion failed");
    return out;
}
std::string quote(const std::string &v) {
    std::string out = "\"";
    constexpr char digits[] = "0123456789abcdef";
    for (const char ch : v) {
        const auto c = static_cast<unsigned char>(ch);
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20 || c == 0x7f) {
                out += "\\u00";
                out += digits[static_cast<unsigned int>(c) >> 4u];
                out += digits[static_cast<unsigned int>(c) & 15u];
            } else
                out += ch;
        }
    }
    return out + '"';
}
bool write_output(const std::string &v, bool error) {
    const auto handle = GetStdHandle(error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    if (handle == INVALID_HANDLE_VALUE || handle == nullptr)
        return false;
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode)) {
        const auto w = wide(v);
        std::size_t offset = 0;
        while (offset < w.size()) {
            DWORD done = 0;
            const auto count = static_cast<DWORD>((std::min)(w.size() - offset, std::size_t{16384}));
            if (!WriteConsoleW(handle, w.data() + offset, count, &done, nullptr) || done == 0)
                return false;
            offset += done;
        }
    } else {
        std::size_t offset = 0;
        while (offset < v.size()) {
            DWORD done = 0;
            const auto count = static_cast<DWORD>((std::min)(v.size() - offset, std::size_t{65536}));
            if (!WriteFile(handle, v.data() + offset, count, &done, nullptr) || done == 0)
                return false;
            offset += done;
        }
    }
    return true;
}
} // namespace npa
