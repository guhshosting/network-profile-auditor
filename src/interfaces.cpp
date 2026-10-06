#include "windows_support.hpp"
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
namespace npa {
void acquire_interfaces(Result &r) {
    PMIB_IF_TABLE2 table = nullptr;
    const auto status = GetIfTable2(&table);
    const std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> owner(table, &FreeMibTable);
    if (status != NO_ERROR) {
        r.warnings.push_back("IP Helper interface table unavailable (Win32 " + std::to_string(status) + ").");
        return;
    }
    if (!table) {
        r.warnings.push_back("IP Helper returned an empty table pointer.");
        return;
    }
    r.interface_api_available = true;
    for (ULONG j = 0; j < table->NumEntries; ++j) {
        const auto &row = table->Table[j];
        Interface i;
        i.id = guid(row.InterfaceGuid);
        i.name = utf8(row.Alias);
        i.description = utf8(row.Description);
        i.index = row.InterfaceIndex;
        i.luid = row.InterfaceLuid.Value;
        i.type = row.Type;
        i.oper_status = static_cast<std::uint32_t>(row.OperStatus);
        i.tunnel_type = static_cast<std::uint32_t>(row.TunnelType);
        i.hardware = row.InterfaceAndOperStatusFlags.HardwareInterface != 0;
        i.filter = row.InterfaceAndOperStatusFlags.FilterInterface != 0;
        r.interfaces.push_back(std::move(i));
    }
}
} // namespace npa
