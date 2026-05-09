#ifndef GMODOFFSETDUMPER_H
#define GMODOFFSETDUMPER_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <iosfwd>
#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

struct RemoteModuleInfo {
    std::string name;
    uintptr_t base;
    size_t size;
    std::string path;
};

enum class ResolverKind {
    MatchAddress,
    RipRelative32,
    ClientClassRecvTable,
    InterfaceInstance
};

struct PatternDefinition {
    std::string name;
    std::string moduleName;
    std::vector<std::uint8_t> bytes;
    std::string mask;
    ResolverKind resolverKind;
    std::uint32_t instructionOffset;
    std::uint32_t displacementOffset;
    std::uint32_t instructionSize;
    std::string lookupName;
};

struct ResolvedOffset {
    std::string name;
    std::string moduleName;
    uintptr_t address;
    uintptr_t value;
    bool found;
};

struct NetvarEntry {
    std::string tableName;
    std::string identifier;
    uintptr_t offset;
    std::uint32_t stride;
    std::uint32_t elementCount;
    bool isArray;
};

struct NetvarTable {
    std::string name;
    std::vector<NetvarEntry> entries;
};

class GModOffsetDumper {
private:
    DWORD processId;
    HANDLE hProcess;
    std::string processName;
    std::string processPath;
    std::unordered_map<std::string, RemoteModuleInfo> modules;
    std::vector<ResolvedOffset> cachedStaticOffsets;
    std::vector<NetvarTable> cachedNetvarTables;
    std::size_t cachedClientClassCount;
    std::size_t cachedNetvarCount;

    bool FindGModProcess();
    bool OpenProcessHandle();
    bool LoadRemoteModules();
    bool ValidateRequiredModules() const;
    const RemoteModuleInfo* GetModuleInfo(const std::string& moduleName) const;

    bool ReadMemory(uintptr_t address, void* buffer, size_t size) const;
    bool ReadPointer(uintptr_t address, uintptr_t* value) const;
    bool ReadUint32(uintptr_t address, std::uint32_t* value) const;
    bool ReadString(uintptr_t address, std::string& str, size_t maxLength = 256) const;

    uintptr_t FindPattern(const RemoteModuleInfo& module, const PatternDefinition& pattern) const;
    uintptr_t ResolvePatternAddress(uintptr_t matchAddress, const PatternDefinition& pattern) const;
    uintptr_t ResolveClientClassRecvTable(uintptr_t clientClassHeadSlot, const std::string& networkName) const;
    uintptr_t ResolveInterfaceInstance(uintptr_t interfaceListHeadSlot, const std::string& interfaceName) const;
    uintptr_t ResolveClientClassHeadSlot() const;
    uintptr_t ToModuleOffset(const std::string& moduleName, uintptr_t address) const;

    std::vector<PatternDefinition> BuildPatternRegistry() const;
    std::vector<ResolvedOffset> ResolveStaticOffsets();
    std::vector<NetvarTable> ResolveAllNetvars();
    void WalkRecvTable(uintptr_t recvTableAddress,
                       const std::string& tableName,
                       const std::string& prefix,
                       uintptr_t baseOffset,
                       std::vector<NetvarEntry>& entries,
                       std::unordered_map<std::string, std::size_t>& identifierCounts,
                       std::vector<uintptr_t>& tablePath) const;
    void AddLeafNetvar(const std::string& tableName,
                       const std::string& identifier,
                       uintptr_t offset,
                       std::vector<NetvarEntry>& entries,
                       std::unordered_map<std::string, std::size_t>& identifierCounts) const;
    void AddArrayNetvar(const std::string& tableName,
                        const std::string& identifier,
                        uintptr_t offset,
                        std::uint32_t stride,
                        std::uint32_t elementCount,
                        std::vector<NetvarEntry>& entries,
                        std::unordered_map<std::string, std::size_t>& identifierCounts) const;
    void SortAndDeduplicateNetvars(std::vector<NetvarTable>& tables) const;
    void PrintResolvedOffsets(std::ostream& output, const std::vector<ResolvedOffset>& offsets) const;
    void PrintNetvarSummary(std::ostream& output, const std::vector<NetvarTable>& tables) const;

    static std::string NormalizeModuleName(const std::string& moduleName);
    static std::string SanitizeIdentifier(const std::string& value);
    static bool ShouldSkipNetvar(const std::string& name, std::uint32_t flags);

public:
    GModOffsetDumper();
    ~GModOffsetDumper();

    bool Initialize();
    void DumpAllOffsets();
    bool SaveCppHeader(const std::string& filename);

    std::string GetProcessName() const;
    DWORD GetProcessId() const { return processId; }
    bool IsProcessValid() const { return hProcess != NULL && processId != 0; }
    std::size_t GetClientClassCount() const { return cachedClientClassCount; }
    std::size_t GetNetvarCount() const { return cachedNetvarCount; }

    void PrintProcessInfo() const;
    void PrintMemoryDump(uintptr_t address, size_t size) const;
};

#endif // GMODOFFSETDUMPER_H
