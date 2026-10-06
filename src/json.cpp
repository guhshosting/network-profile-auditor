#include "npa.hpp"
#include <sstream>
namespace npa {
namespace {
std::string str(const std::optional<std::string> &v) { return v ? quote(*v) : "null"; }
template <class T> std::string num(const std::optional<T> &v) { return v ? std::to_string(*v) : "null"; }
std::string boolean(const std::optional<bool> &v) { return v ? (*v ? "true" : "false") : "null"; }
void strings(std::ostream &s, const std::vector<std::string> &items) {
    s << '[';
    bool first = true;
    for (const auto &v : items) {
        if (!first)
            s << ',';
        first = false;
        s << quote(v);
    }
    s << ']';
}
void state(std::ostream &s, std::optional<std::uint32_t> conn, std::optional<std::uint32_t> dom) {
    s << ",\"windows_connectivity_raw\":" << num(conn) << ",\"windows_connectivity_flags\":";
    strings(s, connectivity(conn));
    s << ",\"domain_type_raw\":" << num(dom) << ",\"domain_type\":" << quote(domain(dom));
}
} // namespace
std::string json(const Result &r) {
    std::ostringstream s;
    s << "{\"schema_version\":\"1.0\",\"application_version\":\"" << version
      << "\",\"selection\":" << quote(r.all ? "all" : "current")
      << ",\"profile_api_available\":" << (r.profile_api_available ? "true" : "false")
      << ",\"profile_enumeration_complete\":" << (r.profile_enumeration_complete ? "true" : "false")
      << ",\"interface_api_available\":" << (r.interface_api_available ? "true" : "false")
      << ",\"networks\":[";
    bool first = true;
    for (const auto &n : r.networks) {
        if (!first)
            s << ',';
        first = false;
        s << "{\"id\":" << str(n.id) << ",\"name\":" << str(n.name)
          << ",\"connected\":" << boolean(n.connected);
        state(s, n.connectivity, n.domain_type);
        s << '}';
    }
    s << "],\"profiles\":[";
    first = true;
    for (const auto &n : r.networks) {
        if (!first)
            s << ',';
        first = false;
        s << "{\"id\":" << str(n.id) << ",\"network_id\":" << str(n.id) << ",\"name\":" << str(n.name)
          << ",\"category_raw\":" << num(n.category) << ",\"category\":" << quote(category(n.category))
          << '}';
    }
    s << "],\"interfaces\":[";
    first = true;
    for (const auto &i : r.interfaces) {
        if (!first)
            s << ',';
        first = false;
        s << "{\"id\":" << quote(i.id) << ",\"friendly_name\":" << quote(i.name)
          << ",\"description\":" << quote(i.description) << ",\"index\":" << i.index
          << ",\"luid\":" << quote(std::to_string(i.luid)) << ",\"type_raw\":" << i.type
          << ",\"oper_status_raw\":" << i.oper_status << ",\"oper_status\":" << quote(oper(i.oper_status))
          << ",\"tunnel_type_raw\":" << i.tunnel_type
          << ",\"hardware_interface\":" << (i.hardware ? "true" : "false")
          << ",\"filter_interface\":" << (i.filter ? "true" : "false")
          << ",\"virtual_vpn_candidate\":" << (virtual_candidate(i) ? "true" : "false") << '}';
    }
    s << "],\"correlations\":[";
    first = true;
    for (const auto &c : r.correlations) {
        if (!first)
            s << ',';
        first = false;
        s << "{\"network_id\":" << str(c.network_id) << ",\"connection_id\":" << str(c.connection_id)
          << ",\"adapter_id\":" << str(c.adapter_id) << ",\"interface_id\":"
          << (c.interface_index && *c.interface_index < r.interfaces.size()
                  ? quote(r.interfaces[*c.interface_index].id)
                  : "null")
          << ",\"connected\":" << boolean(c.connected);
        state(s, c.connectivity, c.domain_type);
        s << '}';
    }
    s << "],\"findings\":[";
    first = true;
    for (const auto &f : r.findings) {
        if (!first)
            s << ',';
        first = false;
        s << "{\"code\":" << quote(f.code) << ",\"subject\":" << quote(f.subject)
          << ",\"message\":" << quote(f.message) << '}';
    }
    s << "],\"warnings\":";
    strings(s, r.warnings);
    s << ",\"limitations\":";
    strings(s, r.limitations);
    s << "}\n";
    return s.str();
}
} // namespace npa
