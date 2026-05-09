#include "GModOffsetDumper.h"

#include <psapi.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <unordered_set>

#pragma comment(lib, "psapi.lib")

namespace {

constexpr DWORD kProcessAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
constexpr DWORD kModuleListFilter = LIST_MODULES_ALL;
constexpr size_t kPatternChunkSize = 1024 * 1024;
constexpr std::uint32_t kPropFlagExclude = 0x40;

enum class RecvPropType : std::int32_t {
    Int = 0,
    Float = 1,
    Vector = 2,
    VectorXY = 3,
    String = 4,
    Array = 5,
    DataTable = 6,
    Int64 = 7
};

struct RemoteClientClass {
    uintptr_t createFn;
    uintptr_t createEventFn;
    uintptr_t networkName;
    uintptr_t recvTable;
    uintptr_t next;
    std::uint32_t classId;
    std::uint32_t reserved;
};

struct RemoteRecvTable {
    uintptr_t props;
    std::int32_t propCount;
    std::int32_t reserved0;
    uintptr_t decoder;
    uintptr_t netTableName;
    std::uint8_t initialized;
    std::uint8_t inMainList;
    std::uint8_t reserved1[6];
};

struct RemoteRecvProp {
    uintptr_t varName;
    std::int32_t recvType;
    std::uint32_t flags;
    std::uint32_t stringBufferSize;
    std::uint8_t insideArray;
    std::uint8_t reserved0[3];
    uintptr_t extraData;
    uintptr_t arrayProp;
    uintptr_t arrayLengthProxy;
    uintptr_t proxyFn;
    uintptr_t dataTableProxyFn;
    uintptr_t dataTable;
    std::int32_t offset;
    std::int32_t elementStride;
    std::int32_t elementCount;
    std::int32_t reserved1;
    uintptr_t parentArrayPropName;
};

static_assert(sizeof(RemoteClientClass) == 0x30, "Unexpected RemoteClientClass size");
static_assert(sizeof(RemoteRecvTable) == 0x28, "Unexpected RemoteRecvTable size");
static_assert(sizeof(RemoteRecvProp) == 0x60, "Unexpected RemoteRecvProp size");

template <typename T>
PatternDefinition MakePattern(const char* name,
                              const char* moduleName,
                              T bytes,
                              std::string mask,
                              ResolverKind resolverKind,
                              std::uint32_t instructionOffset,
                              std::uint32_t displacementOffset,
                              std::uint32_t instructionSize,
                              std::string lookupName = {}) {
    return PatternDefinition{
        name,
        moduleName,
        std::vector<std::uint8_t>(bytes.begin(), bytes.end()),
        std::move(mask),
        resolverKind,
        instructionOffset,
        displacementOffset,
        instructionSize,
        std::move(lookupName),
    };
}

std::string FormatHex(uintptr_t value) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << value;
    return stream.str();
}

std::string MakeUniqueIdentifier(const std::string& baseIdentifier,
                                 uintptr_t offset,
                                 std::unordered_map<std::string, std::size_t>& identifierCounts) {
    const auto [it, inserted] = identifierCounts.emplace(baseIdentifier, 0U);
    if (inserted) {
        return baseIdentifier;
    }

    ++it->second;

    std::ostringstream stream;
    stream << baseIdentifier << "__" << std::uppercase << std::hex << offset;
    const std::string offsetKey = stream.str();
    if (identifierCounts.emplace(offsetKey, 0U).second) {
        return offsetKey;
    }

    std::string numberedKey;
    do {
        ++it->second;
        numberedKey = baseIdentifier + "__" + std::to_string(it->second);
    } while (!identifierCounts.emplace(numberedKey, 0U).second);

    return numberedKey;
}

} // namespace

GModOffsetDumper::GModOffsetDumper()
    : processId(0),
      hProcess(NULL),
      cachedClientClassCount(0),
      cachedNetvarCount(0) {
}

GModOffsetDumper::~GModOffsetDumper() {
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
    }
}

std::string GModOffsetDumper::NormalizeModuleName(const std::string& moduleName) {
    std::string normalized = moduleName;
    std::transform(
        normalized.begin(),
        normalized.end(),
        normalized.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return normalized;
}

std::string GModOffsetDumper::SanitizeIdentifier(const std::string& value) {
    std::string sanitized;
    sanitized.reserve(value.size() + 8);

    bool lastWasUnderscore = false;
    for (unsigned char ch : value) {
        const bool isAlphaNumeric = std::isalnum(ch) != 0;
        const bool keepCharacter = isAlphaNumeric || ch == '_';

        if (keepCharacter) {
            sanitized.push_back(static_cast<char>(ch));
            lastWasUnderscore = false;
            continue;
        }

        if (!lastWasUnderscore) {
            sanitized.push_back('_');
            lastWasUnderscore = true;
        }
    }

    while (!sanitized.empty() && sanitized.back() == '_') {
        sanitized.pop_back();
    }

    if (sanitized.empty()) {
        sanitized = "value";
    }

    if (std::isdigit(static_cast<unsigned char>(sanitized.front())) != 0) {
        sanitized.insert(sanitized.begin(), '_');
    }

    return sanitized;
}

bool GModOffsetDumper::ShouldSkipNetvar(const std::string& name, std::uint32_t flags) {
    if (name.empty()) {
        return true;
    }

    if ((flags & kPropFlagExclude) != 0U) {
        return true;
    }

    return name == "baseclass";
}

bool GModOffsetDumper::FindGModProcess() {
    DWORD processes[2048] = {};
    DWORD bytesReturned = 0;

    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        return false;
    }

    const DWORD processCount = bytesReturned / sizeof(DWORD);

    for (DWORD i = 0; i < processCount; ++i) {
        if (processes[i] == 0) {
            continue;
        }

        HANDLE candidate = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processes[i]);
        if (candidate == NULL) {
            continue;
        }

        char imagePath[MAX_PATH] = {};
        DWORD imagePathLength = static_cast<DWORD>(sizeof(imagePath));

        if (QueryFullProcessImageNameA(candidate, 0, imagePath, &imagePathLength) != 0) {
            std::string path = NormalizeModuleName(imagePath);
            const size_t slash = path.find_last_of("\\/");
            const std::string name = slash == std::string::npos ? path : path.substr(slash + 1);

            if (name == "gmod.exe" && path.find("\\bin\\win64\\") != std::string::npos) {
                processId = processes[i];
                processName = "gmod.exe";
                processPath = imagePath;
                CloseHandle(candidate);
                return true;
            }
        }

        CloseHandle(candidate);
    }

    return false;
}

bool GModOffsetDumper::OpenProcessHandle() {
    if (processId == 0) {
        return false;
    }

    hProcess = OpenProcess(kProcessAccess, FALSE, processId);
    return hProcess != NULL;
}

bool GModOffsetDumper::LoadRemoteModules() {
    modules.clear();

    if (!hProcess) {
        return false;
    }

    DWORD needed = 0;
    std::vector<HMODULE> moduleHandles(256);

    if (!EnumProcessModulesEx(
            hProcess,
            moduleHandles.data(),
            static_cast<DWORD>(moduleHandles.size() * sizeof(HMODULE)),
            &needed,
            kModuleListFilter)) {
        return false;
    }

    if (needed > moduleHandles.size() * sizeof(HMODULE)) {
        moduleHandles.resize(needed / sizeof(HMODULE));
        if (!EnumProcessModulesEx(
                hProcess,
                moduleHandles.data(),
                static_cast<DWORD>(moduleHandles.size() * sizeof(HMODULE)),
                &needed,
                kModuleListFilter)) {
            return false;
        }
    }

    const size_t moduleCount = needed / sizeof(HMODULE);
    for (size_t i = 0; i < moduleCount; ++i) {
        char moduleName[MAX_PATH] = {};
        char modulePath[MAX_PATH] = {};
        MODULEINFO moduleInfo = {};

        if (GetModuleBaseNameA(hProcess, moduleHandles[i], moduleName, static_cast<DWORD>(sizeof(moduleName))) == 0) {
            continue;
        }

        if (!GetModuleInformation(hProcess, moduleHandles[i], &moduleInfo, sizeof(moduleInfo))) {
            continue;
        }

        GetModuleFileNameExA(hProcess, moduleHandles[i], modulePath, static_cast<DWORD>(sizeof(modulePath)));

        RemoteModuleInfo info;
        info.name = moduleName;
        info.base = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
        info.size = moduleInfo.SizeOfImage;
        info.path = modulePath;

        modules.emplace(NormalizeModuleName(moduleName), std::move(info));
    }

    return !modules.empty();
}

bool GModOffsetDumper::ValidateRequiredModules() const {
    return GetModuleInfo("client.dll") != nullptr && GetModuleInfo("engine.dll") != nullptr;
}

const RemoteModuleInfo* GModOffsetDumper::GetModuleInfo(const std::string& moduleName) const {
    const auto it = modules.find(NormalizeModuleName(moduleName));
    return it != modules.end() ? &it->second : nullptr;
}

bool GModOffsetDumper::Initialize() {
    cachedStaticOffsets.clear();
    cachedNetvarTables.clear();
    modules.clear();
    cachedClientClassCount = 0;
    cachedNetvarCount = 0;
    processId = 0;
    processName.clear();
    processPath.clear();

    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        hProcess = NULL;
    }

    if (!FindGModProcess()) {
        std::cout << "gmod.exe bulunamadi veya win64 surumu acik degil." << std::endl;
        return false;
    }

    if (!OpenProcessHandle()) {
        std::cout << "Surec handle'i acilamadi." << std::endl;
        return false;
    }

    if (!LoadRemoteModules()) {
        std::cout << "Uzak moduller okunamadi." << std::endl;
        return false;
    }

    if (!ValidateRequiredModules()) {
        std::cout << "client.dll veya engine.dll yuklu degil." << std::endl;
        return false;
    }

    return true;
}

bool GModOffsetDumper::ReadMemory(uintptr_t address, void* buffer, size_t size) const {
    if (!hProcess || address == 0 || !buffer || size == 0) {
        return false;
    }

    SIZE_T bytesRead = 0;
    return ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) && bytesRead == size;
}

bool GModOffsetDumper::ReadPointer(uintptr_t address, uintptr_t* value) const {
    return ReadMemory(address, value, sizeof(uintptr_t));
}

bool GModOffsetDumper::ReadUint32(uintptr_t address, std::uint32_t* value) const {
    return ReadMemory(address, value, sizeof(std::uint32_t));
}

bool GModOffsetDumper::ReadString(uintptr_t address, std::string& str, size_t maxLength) const {
    str.clear();

    if (address == 0 || maxLength == 0) {
        return false;
    }

    std::vector<char> buffer(maxLength + 1, '\0');
    if (!ReadMemory(address, buffer.data(), maxLength)) {
        return false;
    }

    buffer[maxLength] = '\0';
    str.assign(buffer.data());
    return true;
}

uintptr_t GModOffsetDumper::FindPattern(const RemoteModuleInfo& module, const PatternDefinition& pattern) const {
    const size_t patternLength = pattern.mask.size();
    if (patternLength == 0 || pattern.bytes.size() != patternLength || module.size < patternLength) {
        return 0;
    }

    const size_t chunkSize = std::max(kPatternChunkSize, patternLength);
    const size_t overlap = patternLength > 0 ? patternLength - 1 : 0;
    const size_t step = chunkSize > overlap ? chunkSize - overlap : chunkSize;
    const uintptr_t moduleEnd = module.base + module.size;

    std::vector<std::uint8_t> buffer(chunkSize);

    for (uintptr_t chunkStart = module.base; chunkStart < moduleEnd; chunkStart += step) {
        const size_t readSize =
            static_cast<size_t>(std::min<uintptr_t>(moduleEnd - chunkStart, static_cast<uintptr_t>(chunkSize)));

        if (!ReadMemory(chunkStart, buffer.data(), readSize)) {
            continue;
        }

        for (size_t i = 0; i + patternLength <= readSize; ++i) {
            bool matched = true;
            for (size_t j = 0; j < patternLength; ++j) {
                if (pattern.mask[j] != '?' && buffer[i + j] != pattern.bytes[j]) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                return chunkStart + i;
            }
        }
    }

    return 0;
}

uintptr_t GModOffsetDumper::ResolveClientClassRecvTable(uintptr_t clientClassHeadSlot, const std::string& networkName) const {
    uintptr_t current = 0;
    if (!ReadPointer(clientClassHeadSlot, &current) || current == 0) {
        return 0;
    }

    std::unordered_set<uintptr_t> visited;
    while (current != 0 && visited.insert(current).second) {
        RemoteClientClass remoteClass{};
        if (!ReadMemory(current, &remoteClass, sizeof(remoteClass))) {
            return 0;
        }

        std::string name;
        if (!ReadString(remoteClass.networkName, name, 128)) {
            return 0;
        }

        if (name == networkName) {
            return remoteClass.recvTable;
        }

        current = remoteClass.next;
    }

    return 0;
}

uintptr_t GModOffsetDumper::ResolveInterfaceInstance(uintptr_t interfaceListHeadSlot, const std::string& interfaceName) const {
    struct RemoteInterfaceReg {
        uintptr_t createFn;
        uintptr_t name;
        uintptr_t next;
    };

    uintptr_t current = 0;
    if (!ReadPointer(interfaceListHeadSlot, &current) || current == 0) {
        return 0;
    }

    std::unordered_set<uintptr_t> visited;
    while (current != 0 && visited.insert(current).second) {
        RemoteInterfaceReg reg{};
        if (!ReadMemory(current, &reg, sizeof(reg))) {
            return 0;
        }

        std::string name;
        if (!ReadString(reg.name, name, 128)) {
            return 0;
        }

        if (name == interfaceName) {
            std::array<std::uint8_t, 8> createStub{};
            if (!ReadMemory(reg.createFn, createStub.data(), createStub.size())) {
                return 0;
            }

            if (createStub[0] == 0x48 && createStub[1] == 0x8D && createStub[2] == 0x05) {
                std::int32_t displacement = 0;
                std::memcpy(&displacement, createStub.data() + 3, sizeof(displacement));
                return reg.createFn + 7 + displacement;
            }

            if (createStub[0] == 0x48 && createStub[1] == 0x8B && createStub[2] == 0x05) {
                std::int32_t displacement = 0;
                std::memcpy(&displacement, createStub.data() + 3, sizeof(displacement));

                uintptr_t instanceSlot = reg.createFn + 7 + displacement;
                uintptr_t instance = 0;
                return ReadPointer(instanceSlot, &instance) ? instance : 0;
            }

            return 0;
        }

        current = reg.next;
    }

    return 0;
}

uintptr_t GModOffsetDumper::ResolveClientClassHeadSlot() const {
    const RemoteModuleInfo* module = GetModuleInfo("client.dll");
    if (!module) {
        return 0;
    }

    const PatternDefinition pattern = MakePattern(
        "ClientClassHead",
        "client.dll",
        std::array<std::uint8_t, 44>{
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0xD1, 0x48, 0x85, 0xC9, 0x74, 0x11},
        std::string("xxx????x") + "xxxxxxxx" + "xxx????x" + "xxxxxxxx" + "xxxxxxxxxxxx",
        ResolverKind::RipRelative32,
        0,
        3,
        7);

    const uintptr_t matchAddress = FindPattern(*module, pattern);
    return ResolvePatternAddress(matchAddress, pattern);
}

uintptr_t GModOffsetDumper::ResolvePatternAddress(uintptr_t matchAddress, const PatternDefinition& pattern) const {
    if (matchAddress == 0) {
        return 0;
    }

    if (pattern.resolverKind == ResolverKind::MatchAddress) {
        return matchAddress;
    }

    const uintptr_t instructionAddress = matchAddress + pattern.instructionOffset;
    std::int32_t displacement = 0;

    if (!ReadMemory(instructionAddress + pattern.displacementOffset, &displacement, sizeof(displacement))) {
        return 0;
    }

    const uintptr_t resolvedAddress = instructionAddress + pattern.instructionSize + displacement;

    if (pattern.resolverKind == ResolverKind::RipRelative32) {
        return resolvedAddress;
    }

    if (pattern.resolverKind == ResolverKind::ClientClassRecvTable) {
        return ResolveClientClassRecvTable(resolvedAddress, pattern.lookupName);
    }

    if (pattern.resolverKind == ResolverKind::InterfaceInstance) {
        return ResolveInterfaceInstance(resolvedAddress, pattern.lookupName);
    }

    return 0;
}

uintptr_t GModOffsetDumper::ToModuleOffset(const std::string& moduleName, uintptr_t address) const {
    const RemoteModuleInfo* module = GetModuleInfo(moduleName);
    if (!module || address < module->base || address >= module->base + module->size) {
        return address;
    }

    return address - module->base;
}

std::vector<PatternDefinition> GModOffsetDumper::BuildPatternRegistry() const {
    return {
        MakePattern(
            "CClientState",
            "engine.dll",
            std::array<std::uint8_t, 11>{0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x06, 0x0F, 0x94, 0xC0, 0xC3},
            "xx????xxxxx",
            ResolverKind::RipRelative32,
            0,
            2,
            7),
        MakePattern(
            "CClientEntityList",
            "client.dll",
            std::array<std::uint8_t, 33>{
                0x48, 0x89, 0x5C, 0x24, 0x08,
                0x48, 0x89, 0x74, 0x24, 0x10,
                0x57, 0x48, 0x83, 0xEC, 0x20,
                0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xF1, 0x48, 0x85, 0xDB, 0x74, 0x19},
            "xxxxxxxxxxxxxxxxxx????xxxxxxxxxxx",
            ResolverKind::InterfaceInstance,
            15,
            3,
            7,
            "VClientEntityList003"),
        MakePattern(
            "CLocalPlayer",
            "engine.dll",
            std::array<std::uint8_t, 9>{0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xC0, 0xC3},
            "xx????xxx",
            ResolverKind::RipRelative32,
            0,
            2,
            6),
        MakePattern(
            "ViewAngles",
            "engine.dll",
            std::array<std::uint8_t, 39>{
                0xF3, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00,
                0xF3, 0x0F, 0x11, 0x02,
                0xF3, 0x0F, 0x10, 0x0D, 0x00, 0x00, 0x00, 0x00,
                0xF3, 0x0F, 0x11, 0x4A, 0x04,
                0xF3, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00,
                0xF3, 0x0F, 0x11, 0x42, 0x08, 0xC3},
            std::string("xxxx????") + "xxxx" + "xxxx????" + "xxxxx" + "xxxx????" + "xxxxxx",
            ResolverKind::RipRelative32,
            0,
            4,
            8),
        MakePattern(
            "GlobalVars",
            "client.dll",
            std::array<std::uint8_t, 30>{
                0x53, 0x48, 0x83, 0xEC, 0x40,
                0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
                0x0F, 0xB6, 0xDA,
                0x0F, 0x29, 0x74, 0x24, 0x30,
                0x0F, 0x29, 0x7C, 0x24, 0x20,
                0xF3, 0x0F, 0x10, 0x78, 0x18},
            "xxxxxxxx????xxxxxxxxxxxxxxxxxx",
            ResolverKind::RipRelative32,
            5,
            3,
            7),
        MakePattern(
            "PlayerResourceTable",
            "client.dll",
            std::array<std::uint8_t, 44>{
                0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3,
                0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3,
                0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0xD1, 0x48, 0x85, 0xC9, 0x74, 0x11},
            std::string("xxx????x") + "xxxxxxxx" + "xxx????x" + "xxxxxxxx" + "xxxxxxxxxxxx",
            ResolverKind::ClientClassRecvTable,
            0,
            3,
            7,
            "CPlayerResource"),
    };
}

std::vector<ResolvedOffset> GModOffsetDumper::ResolveStaticOffsets() {
    const auto patterns = BuildPatternRegistry();
    std::vector<ResolvedOffset> results;
    results.reserve(patterns.size());

    for (const PatternDefinition& pattern : patterns) {
        ResolvedOffset resolved{};
        resolved.name = pattern.name;
        resolved.moduleName = pattern.moduleName;
        resolved.address = 0;
        resolved.value = 0;
        resolved.found = false;

        const RemoteModuleInfo* module = GetModuleInfo(pattern.moduleName);
        if (!module) {
            results.push_back(std::move(resolved));
            continue;
        }

        const uintptr_t matchAddress = FindPattern(*module, pattern);
        if (matchAddress == 0) {
            results.push_back(std::move(resolved));
            continue;
        }

        const uintptr_t absoluteAddress = ResolvePatternAddress(matchAddress, pattern);
        if (absoluteAddress == 0) {
            results.push_back(std::move(resolved));
            continue;
        }

        resolved.address = absoluteAddress;
        resolved.value = ToModuleOffset(pattern.moduleName, absoluteAddress);
        resolved.found = true;
        results.push_back(std::move(resolved));
    }

    cachedStaticOffsets = results;
    return results;
}

void GModOffsetDumper::AddLeafNetvar(const std::string& tableName,
                                     const std::string& identifier,
                                     uintptr_t offset,
                                     std::vector<NetvarEntry>& entries,
                                     std::unordered_map<std::string, std::size_t>& identifierCounts) const {
    NetvarEntry entry{};
    entry.tableName = tableName;
    entry.identifier = MakeUniqueIdentifier(identifier, offset, identifierCounts);
    entry.offset = offset;
    entry.stride = 0;
    entry.elementCount = 0;
    entry.isArray = false;
    entries.push_back(std::move(entry));
}

void GModOffsetDumper::AddArrayNetvar(const std::string& tableName,
                                      const std::string& identifier,
                                      uintptr_t offset,
                                      std::uint32_t stride,
                                      std::uint32_t elementCount,
                                      std::vector<NetvarEntry>& entries,
                                      std::unordered_map<std::string, std::size_t>& identifierCounts) const {
    NetvarEntry entry{};
    entry.tableName = tableName;
    entry.identifier = MakeUniqueIdentifier(identifier, offset, identifierCounts);
    entry.offset = offset;
    entry.stride = stride;
    entry.elementCount = elementCount;
    entry.isArray = true;
    entries.push_back(std::move(entry));
}

void GModOffsetDumper::WalkRecvTable(uintptr_t recvTableAddress,
                                     const std::string& tableName,
                                     const std::string& prefix,
                                     uintptr_t baseOffset,
                                     std::vector<NetvarEntry>& entries,
                                     std::unordered_map<std::string, std::size_t>& identifierCounts,
                                     std::vector<uintptr_t>& tablePath) const {
    if (recvTableAddress == 0) {
        return;
    }

    if (std::find(tablePath.begin(), tablePath.end(), recvTableAddress) != tablePath.end()) {
        return;
    }

    tablePath.push_back(recvTableAddress);

    RemoteRecvTable table{};
    if (!ReadMemory(recvTableAddress, &table, sizeof(table)) || table.props == 0 || table.propCount <= 0) {
        tablePath.pop_back();
        return;
    }

    for (std::int32_t index = 0; index < table.propCount; ++index) {
        RemoteRecvProp prop{};
        const uintptr_t propAddress = table.props + static_cast<uintptr_t>(index) * sizeof(RemoteRecvProp);
        if (!ReadMemory(propAddress, &prop, sizeof(prop))) {
            continue;
        }

        std::string rawName;
        if (!ReadString(prop.varName, rawName, 256)) {
            continue;
        }

        if (ShouldSkipNetvar(rawName, prop.flags)) {
            continue;
        }

        const std::string sanitizedName = SanitizeIdentifier(rawName);
        const std::string fullName = prefix.empty() ? sanitizedName : prefix + sanitizedName;
        const uintptr_t currentOffset = baseOffset + static_cast<uintptr_t>(static_cast<std::uint32_t>(prop.offset));
        const bool isArray = prop.recvType == static_cast<std::int32_t>(RecvPropType::Array);
        const bool isDataTable = prop.recvType == static_cast<std::int32_t>(RecvPropType::DataTable) && prop.dataTable != 0;

        if (isArray) {
            const std::uint32_t stride = prop.elementStride > 0 ? static_cast<std::uint32_t>(prop.elementStride) : 0U;
            const std::uint32_t elementCount = prop.elementCount > 0 ? static_cast<std::uint32_t>(prop.elementCount) : 0U;
            AddArrayNetvar(tableName, fullName, currentOffset, stride, elementCount, entries, identifierCounts);

            if (prop.arrayProp != 0 && stride != 0U && elementCount != 0U) {
                RemoteRecvProp elementProp{};
                if (ReadMemory(prop.arrayProp, &elementProp, sizeof(elementProp)) &&
                    elementProp.recvType == static_cast<std::int32_t>(RecvPropType::DataTable) &&
                    elementProp.dataTable != 0) {
                    for (std::uint32_t elementIndex = 0; elementIndex < elementCount; ++elementIndex) {
                        const std::string elementPrefix = fullName + "_" + std::to_string(elementIndex) + "_";
                        const uintptr_t elementOffset =
                            currentOffset +
                            static_cast<uintptr_t>(elementIndex) * static_cast<uintptr_t>(stride) +
                            static_cast<uintptr_t>(static_cast<std::uint32_t>(elementProp.offset));
                        WalkRecvTable(
                            elementProp.dataTable,
                            tableName,
                            elementPrefix,
                            elementOffset,
                            entries,
                            identifierCounts,
                            tablePath);
                    }
                }
            }

            continue;
        }

        if (isDataTable) {
            WalkRecvTable(
                prop.dataTable,
                tableName,
                fullName + "_",
                currentOffset,
                entries,
                identifierCounts,
                tablePath);
            continue;
        }

        AddLeafNetvar(tableName, fullName, currentOffset, entries, identifierCounts);
    }

    tablePath.pop_back();
}

void GModOffsetDumper::SortAndDeduplicateNetvars(std::vector<NetvarTable>& tables) const {
    std::sort(
        tables.begin(),
        tables.end(),
        [](const NetvarTable& left, const NetvarTable& right) { return left.name < right.name; });

    for (NetvarTable& table : tables) {
        std::sort(
            table.entries.begin(),
            table.entries.end(),
            [](const NetvarEntry& left, const NetvarEntry& right) {
                if (left.offset != right.offset) {
                    return left.offset < right.offset;
                }
                return left.identifier < right.identifier;
            });

        table.entries.erase(
            std::unique(
                table.entries.begin(),
                table.entries.end(),
                [](const NetvarEntry& left, const NetvarEntry& right) {
                    return left.identifier == right.identifier && left.offset == right.offset && left.isArray == right.isArray;
                }),
            table.entries.end());
    }
}

std::vector<NetvarTable> GModOffsetDumper::ResolveAllNetvars() {
    const uintptr_t clientClassHeadSlot = ResolveClientClassHeadSlot();
    if (clientClassHeadSlot == 0) {
        cachedNetvarTables.clear();
        cachedClientClassCount = 0;
        cachedNetvarCount = 0;
        return {};
    }

    uintptr_t current = 0;
    if (!ReadPointer(clientClassHeadSlot, &current) || current == 0) {
        cachedNetvarTables.clear();
        cachedClientClassCount = 0;
        cachedNetvarCount = 0;
        return {};
    }

    std::vector<NetvarTable> tables;
    std::unordered_set<uintptr_t> visitedClasses;
    std::unordered_set<uintptr_t> visitedRecvTables;
    cachedClientClassCount = 0;

    while (current != 0 && visitedClasses.insert(current).second) {
        ++cachedClientClassCount;

        RemoteClientClass remoteClass{};
        if (!ReadMemory(current, &remoteClass, sizeof(remoteClass))) {
            break;
        }

        if (remoteClass.recvTable != 0 && visitedRecvTables.insert(remoteClass.recvTable).second) {
            RemoteRecvTable recvTable{};
            if (ReadMemory(remoteClass.recvTable, &recvTable, sizeof(recvTable)) && recvTable.netTableName != 0) {
                std::string tableName;
                if (ReadString(recvTable.netTableName, tableName, 128) && !tableName.empty()) {
                    NetvarTable table;
                    table.name = SanitizeIdentifier(tableName);

                    std::unordered_map<std::string, std::size_t> identifierCounts;
                    std::vector<uintptr_t> tablePath;
                    WalkRecvTable(
                        remoteClass.recvTable,
                        table.name,
                        std::string(),
                        0,
                        table.entries,
                        identifierCounts,
                        tablePath);

                    if (!table.entries.empty()) {
                        tables.push_back(std::move(table));
                    }
                }
            }
        }

        current = remoteClass.next;
    }

    SortAndDeduplicateNetvars(tables);

    cachedNetvarCount = 0;
    for (const NetvarTable& table : tables) {
        cachedNetvarCount += table.entries.size();
    }

    cachedNetvarTables = tables;
    return tables;
}

void GModOffsetDumper::PrintResolvedOffsets(std::ostream& output, const std::vector<ResolvedOffset>& offsets) const {
    output << "\nStatic Offsets:\n";
    output << "===============\n";

    std::ios_base::fmtflags flags = output.flags();

    for (const ResolvedOffset& offset : offsets) {
        output << offset.name << ": ";
        if (offset.found) {
            output << "0x" << std::uppercase << std::hex << offset.value;
        } else {
            output << "Not found";
        }
        output << '\n';
        output.flags(flags);
    }
}

void GModOffsetDumper::PrintNetvarSummary(std::ostream& output, const std::vector<NetvarTable>& tables) const {
    output << "\nNetVar Summary:\n";
    output << "===============\n";
    output << "Client classes: " << cachedClientClassCount << '\n';
    output << "Recv tables: " << tables.size() << '\n';
    output << "Netvars: " << cachedNetvarCount << '\n';
}

void GModOffsetDumper::DumpAllOffsets() {
    if (!IsProcessValid()) {
        std::cout << "Invalid process!" << std::endl;
        return;
    }

    std::cout << "GMOD Full Offset Dumper Starting..." << std::endl;
    std::cout << "Process ID: " << processId << std::endl;
    std::cout << "Process Name: " << GetProcessName() << std::endl;

    const std::vector<ResolvedOffset> staticOffsets = ResolveStaticOffsets();
    const std::vector<NetvarTable> netvarTables = ResolveAllNetvars();

    PrintResolvedOffsets(std::cout, staticOffsets);
    PrintNetvarSummary(std::cout, netvarTables);
}

bool GModOffsetDumper::SaveCppHeader(const std::string& filename) {
    if (cachedStaticOffsets.empty()) {
        ResolveStaticOffsets();
    }

    if (cachedNetvarTables.empty()) {
        ResolveAllNetvars();
    }

    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cout << "Failed to open file: " << filename << std::endl;
        return false;
    }

    file << "#pragma once\n\n";
    file << "#include <cstdint>\n\n";
    file << "// Generated by GMOD Full Offset Dumper\n";
    file << "// Process: " << GetProcessName() << "\n";
    file << "// Path: " << processPath << "\n\n";

    file << "namespace Offsets {\n";
    for (const ResolvedOffset& offset : cachedStaticOffsets) {
        if (!offset.found) {
            file << "inline constexpr std::uintptr_t " << offset.name << " = 0;\n";
            continue;
        }

        file << "inline constexpr std::uintptr_t " << offset.name << " = " << FormatHex(offset.value) << ";\n";
    }
    file << "} // namespace Offsets\n\n";

    file << "namespace NetVars {\n\n";

    for (const NetvarTable& table : cachedNetvarTables) {
        file << "namespace " << table.name << " {\n";

        for (const NetvarEntry& entry : table.entries) {
            if (!entry.isArray) {
                file << "inline constexpr std::uintptr_t " << entry.identifier << " = " << FormatHex(entry.offset) << ";\n";
                continue;
            }

            file << "inline constexpr std::uintptr_t " << entry.identifier << "_array_base = " << FormatHex(entry.offset) << ";\n";
            file << "inline constexpr std::uintptr_t " << entry.identifier << "_array_stride = " << FormatHex(entry.stride) << ";\n";
            file << "inline constexpr std::uintptr_t " << entry.identifier << "_array_count = " << FormatHex(entry.elementCount) << ";\n";

            for (std::uint32_t index = 0; index < entry.elementCount; ++index) {
                const uintptr_t indexedOffset =
                    entry.offset + static_cast<uintptr_t>(index) * static_cast<uintptr_t>(entry.stride);
                file << "inline constexpr std::uintptr_t " << entry.identifier << "_array_" << index << " = "
                     << FormatHex(indexedOffset) << ";\n";
            }
        }

        file << "} // namespace " << table.name << "\n\n";
    }

    file << "} // namespace NetVars\n";

    std::cout << "Generated header: " << filename << std::endl;
    return true;
}

std::string GModOffsetDumper::GetProcessName() const {
    return processName.empty() ? std::string("Unknown") : processName;
}

void GModOffsetDumper::PrintProcessInfo() const {
    std::cout << "Process Information:\n";
    std::cout << "====================\n";
    std::cout << "Process ID: " << processId << "\n";
    std::cout << "Process Name: " << GetProcessName() << "\n";
    std::cout << "Process Path: " << processPath << "\n";
    std::cout << "Client DLL: " << (GetModuleInfo("client.dll") ? "Found" : "Not Found") << "\n";
    std::cout << "Engine DLL: " << (GetModuleInfo("engine.dll") ? "Found" : "Not Found") << "\n";
}

void GModOffsetDumper::PrintMemoryDump(uintptr_t address, size_t size) const {
    if (size == 0) {
        return;
    }

    std::vector<std::uint8_t> buffer(size);
    if (!ReadMemory(address, buffer.data(), size)) {
        return;
    }

    std::ios_base::fmtflags flags = std::cout.flags();

    std::cout << "Memory dump at 0x" << std::hex << std::uppercase << address << " (" << std::dec << size
              << " bytes):\n";
    for (size_t i = 0; i < buffer.size(); ++i) {
        if (i % 16 == 0) {
            std::cout << '\n';
        }

        std::cout << std::setfill('0') << std::setw(2) << std::hex << std::uppercase
                  << static_cast<unsigned int>(buffer[i]) << ' ';
    }
    std::cout << "\n\n";

    std::cout.flags(flags);
}
