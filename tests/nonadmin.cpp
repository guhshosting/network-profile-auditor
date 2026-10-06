// Validation-only launcher. The application itself never creates processes or tokens.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <iostream>
#include <string>
#include <vector>
namespace {
class Handle {
  public:
    HANDLE value = nullptr;
    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE)
            CloseHandle(value);
    }
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
};
class Sid {
  public:
    PSID value = nullptr;
    ~Sid() {
        if (value)
            LocalFree(value);
    }
    Sid() = default;
    Sid(const Sid &) = delete;
    Sid &operator=(const Sid &) = delete;
};
bool unelevated() {
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value))
        return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    if (!GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &size) ||
        elevation.TokenIsElevated)
        return false;
    BOOL admin = TRUE;
    Sid group;
    if (!ConvertStringSidToSidW(L"S-1-5-32-544", &group.value) ||
        !CheckTokenMembership(nullptr, group.value, &admin))
        return false;
    return admin == FALSE;
}
int launch(HANDLE token, const std::wstring &exe, const std::wstring &args) {
    std::wstring command = L"\"" + exe + L"\" " + args;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};
    const bool created =
        token ? CreateProcessAsUserW(token, exe.c_str(), command.data(), nullptr, nullptr, TRUE,
                                     CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE
              : CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                               nullptr, &startup, &process) != FALSE;
    if (!created) {
        std::cerr << "CreateProcessAsUser failed: " << GetLastError() << '\n';
        return 3;
    }
    Handle child(process.hProcess), thread(process.hThread);
    if (WaitForSingleObject(child.value, 30000) != WAIT_OBJECT_0) {
        TerminateProcess(child.value, 4);
        return 4;
    }
    DWORD exit = 4;
    if (!GetExitCodeProcess(child.value, &exit))
        return 4;
    return static_cast<int>(exit);
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && std::wstring(argv[1]) == L"--check") {
        const bool ok = unelevated();
        std::cout << "Unelevated token; Administrators membership disabled: " << (ok ? "PASS" : "FAIL")
                  << '\n';
        return ok ? 0 : 1;
    }
    if (argc != 2)
        return 2;
    if (unelevated()) {
        std::cout << "Current launcher token verified unelevated with Administrators membership disabled.\n"
                  << std::flush;
        return launch(nullptr, argv[1], L"--all --json");
    }
    Handle original, restricted;
    Sid admin, integrity;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                          &original.value) ||
        !ConvertStringSidToSidW(L"S-1-5-32-544", &admin.value) ||
        !ConvertStringSidToSidW(L"S-1-16-8192", &integrity.value)) {
        std::cerr << "Token/SID acquisition failed: " << GetLastError() << '\n';
        return 3;
    }
    SID_AND_ATTRIBUTES deny{admin.value, 0};
    if (!CreateRestrictedToken(original.value, DISABLE_MAX_PRIVILEGE, 1, &deny, 0, nullptr, 0, nullptr,
                               &restricted.value)) {
        std::cerr << "Restricted token failed: " << GetLastError() << '\n';
        return 3;
    }
    TOKEN_MANDATORY_LABEL label{{integrity.value, SE_GROUP_INTEGRITY}};
    if (!SetTokenInformation(restricted.value, TokenIntegrityLevel, &label,
                             static_cast<DWORD>(sizeof(label) + GetLengthSid(integrity.value)))) {
        std::cerr << "Integrity level failed: " << GetLastError() << '\n';
        return 3;
    }
    std::vector<wchar_t> self(32768);
    if (!GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size())))
        return 3;
    const auto verified = launch(restricted.value, self.data(), L"--check");
    if (verified != 0)
        return verified;
    return launch(restricted.value, argv[1], L"--all --json");
}
