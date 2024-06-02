#ifndef ASSEMBLER_HPP
#define ASSEMBLER_HPP

#include <keystone.h>
#include <string>
#include <vector>

class Assembler
{
public:
    explicit Assembler(ks_arch arch = KS_ARCH_X86, ks_mode mode = KS_MODE_32);
    ~Assembler() noexcept;

    void printBytes(const std::string& assemblyCode) noexcept;

private:
    std::vector<unsigned char> assemble(const std::string& assemblyCode) noexcept;

private:
    unsigned char* m_encode = nullptr;
    ks_engine* m_ks;
    ks_arch m_arch;
    ks_mode m_mode;
};

#endif // ASSEMBLER_HPP
