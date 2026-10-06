#include "npa.hpp"
#include <exception>
#include <stdexcept>
int wmain(int argc, wchar_t **argv) {
    try {
        std::vector<std::wstring> args;
        for (int j = 1; j < argc; ++j)
            args.emplace_back(argv[j]);
        const auto options = npa::parse(args);
        if (options.help)
            return npa::write_output(
                       "Usage: network-profile-auditor [--all] [--json]\n       network-profile-auditor "
                       "--help | --version\n\nDefault: current NLM profiles (unknown active state "
                       "retained).\n--all: include disconnected/remembered NLM networks.\n--json: UTF-8 JSON "
                       "schema 1.0; may combine with --all.\nRead-only local metadata; no active probing or "
                       "intentional network communication.\nExit: 0 completed, 2 usage, 3 profile API "
                       "unavailable, 4 unexpected failure.\n")
                       ? 0
                       : 4;
        if (options.version)
            return npa::write_output(std::string("network-profile-auditor ") + npa::version + "\n") ? 0 : 4;
        const auto result = npa::audit(options.all);
        if (!npa::write_output(options.json ? npa::json(result) : npa::human(result)))
            return 4;
        return result.profile_api_available &&
                       (result.profile_enumeration_complete || !result.networks.empty())
                   ? 0
                   : 3;
    } catch (const std::invalid_argument &e) {
        npa::write_output(std::string("Usage error: ") + e.what() + ". Use --help.\n", true);
        return 2;
    } catch (const std::exception &e) {
        npa::write_output(std::string("Unexpected failure: ") + e.what() + "\n", true);
        return 4;
    } catch (...) {
        npa::write_output("Unexpected failure.\n", true);
        return 4;
    }
}
