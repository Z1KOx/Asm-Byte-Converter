#ifndef ASSEMBLER_HPP
#define ASSEMBLER_HPP

#include <keystone.h>
#include <string>
#include <vector>

class Assembler
{
public:
	Assembler();
    ~Assembler() noexcept;

    void printBytes(const std::string& assemblyCode) noexcept;

private:
    std::vector<unsigned char> assemble(const std::string& assemblyCode);

private:
    unsigned char* m_encode{ nullptr };
    ks_engine* m_ks;
    ks_arch m_arch;
    ks_mode m_mode;
};

#endif // ASSEMBLER_HPP
