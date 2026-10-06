#ifndef NPA_WINDOWS_SUPPORT_HPP
#define NPA_WINDOWS_SUPPORT_HPP
#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <memory>
#include <sstream>
#include <stdexcept>
#include "npa.hpp"
namespace npa {
template <class T> class ComPtr {
    T *ptr_ = nullptr;

  public:
    ComPtr() = default;
    ~ComPtr() {
        if (ptr_)
            ptr_->Release();
    }
    ComPtr(const ComPtr &) = delete;
    ComPtr &operator=(const ComPtr &) = delete;
    T *operator->() const { return ptr_; }
    T **put() {
        if (ptr_) {
            ptr_->Release();
            ptr_ = nullptr;
        }
        return &ptr_;
    }
    T *get() const { return ptr_; }
};
class Apartment {
    HRESULT hr_;

  public:
    Apartment() : hr_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}
    ~Apartment() {
        if (SUCCEEDED(hr_))
            CoUninitialize();
    }
    HRESULT status() const { return hr_; }
    Apartment(const Apartment &) = delete;
    Apartment &operator=(const Apartment &) = delete;
};
class Bstr {
    BSTR value_ = nullptr;

  public:
    ~Bstr() { SysFreeString(value_); }
    Bstr() = default;
    Bstr(const Bstr &) = delete;
    Bstr &operator=(const Bstr &) = delete;
    BSTR *put() { return &value_; }
    std::string text() const {
        return value_ ? utf8(std::wstring(value_, SysStringLen(value_))) : std::string{};
    }
};
inline std::string guid(const GUID &value) {
    wchar_t buffer[40]{};
    if (StringFromGUID2(value, buffer, 40) == 0)
        throw std::runtime_error("GUID formatting failed");
    return utf8(buffer);
}
inline void warn(Result &r, const std::string &context, HRESULT hr) {
    r.warnings.push_back(context + " unavailable (HRESULT " + hex(static_cast<std::uint32_t>(hr)) + ").");
}
} // namespace npa
#endif
