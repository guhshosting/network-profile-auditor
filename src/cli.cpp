#include "npa.hpp"
#include <stdexcept>
namespace npa {
Options parse(const std::vector<std::wstring> &args) {
    Options o;
    for (const auto &a : args) {
        if (a == L"--all" && !o.all)
            o.all = true;
        else if (a == L"--json" && !o.json)
            o.json = true;
        else if (a == L"--help" && !o.help)
            o.help = true;
        else if (a == L"--version" && !o.version)
            o.version = true;
        else
            throw std::invalid_argument("Unknown or repeated option");
    }
    if ((o.help || o.version) && args.size() != 1)
        throw std::invalid_argument("--help and --version must be used alone");
    return o;
}
} // namespace npa
