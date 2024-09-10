#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <cstdint>

namespace debugger {

// Resolve a relative path to an absolute path
std::string getAbsolutePath(const std::string& relativePath);

// Get the base address of the program from the /proc/<pid>/maps file
uintptr_t getBaseAddress(pid_t pid, const std::string& filename);

// Get the function offset by its name from the ELF file
uintptr_t getFunctionOffset(const char* program, const std::string& functionName);

std::string toHex(uintptr_t number);
} // namespace debugger

#endif // UTILS_H
