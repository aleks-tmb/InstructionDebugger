#include "utils.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <elfio/elfio.hpp>

namespace debugger {

std::string getAbsolutePath(const std::string& relativePath) {
    std::filesystem::path fsPath(relativePath);
    std::filesystem::path absolutePath = std::filesystem::canonical(fsPath);
    return absolutePath.string();
}

uintptr_t getBaseAddress(pid_t pid, const std::string& filename) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    uintptr_t baseAddress = 0;

    while (std::getline(maps, line)) {
        if (line.find(filename) != std::string::npos ) {
            std::stringstream ss(line);
            std::string addressRange;
            ss >> addressRange;
            baseAddress = std::stoull(addressRange.substr(0, addressRange.find('-')), nullptr, 16);
            break;
        }
    }

    return baseAddress;
}

uintptr_t getFunctionOffset(const char* program, const std::string& functionName) {
    ELFIO::elfio reader;

    // Load the ELF file
    if (!reader.load(program)) {
        return 0;
    }

    // Locate the symbol table
    ELFIO::section* symtab = reader.sections[".symtab"];
    if (!symtab) {
        return 0;
    }

    // Access the symbols
    ELFIO::symbol_section_accessor symbols(reader, symtab);

    for (size_t i = 0; i < symbols.get_symbols_num(); ++i) {
        std::string name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword size;
        unsigned char bind;
        unsigned char type;
        unsigned char other;
        ELFIO::Elf_Half shndx;

        // Get symbol information
        symbols.get_symbol(i, name, value, size, bind, type, shndx, other);
        if (name == functionName) {
            return value;
        }
    }

    return 0;
}

std::string toHex(uintptr_t number) {
    std::stringstream stream;
    stream << "0x" << std::hex << std::setw(16) << std::setfill('0') << number;
    return stream.str();
}

} // namespace debugger
