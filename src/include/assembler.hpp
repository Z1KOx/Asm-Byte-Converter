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

    void printBytes();
    void getUsersOpcode();

private:
    [[nodiscard]] std::vector<unsigned char> assemble();
    [[nodiscard]] bool isValidOpcode() const noexcept;
private:
    unsigned char* m_encode{ nullptr };
    ks_engine* m_ks;
    ks_arch m_arch;
    ks_mode m_mode;

    std::string m_opcode;
};

#endif // ASSEMBLER_HPP