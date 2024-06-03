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

    void getUserOpcode();
    void print() const;

    // Deleted copy constructor, copy assignment operator, move constructor, and move assignment operator
    Assembler(const Assembler& other) = delete;
    Assembler(Assembler&& other) = delete;
    Assembler& operator=(const Assembler& other) = delete;
    Assembler& operator=(Assembler&& other) = delete;

private:
    void printBytes(const std::vector<unsigned char>& bytes) const noexcept;
    void printBinaries(const std::vector<unsigned char>& bytes) const noexcept;

    [[nodiscard]] std::vector<unsigned char> assemble() const; // Assembles the opcode into bytes
    [[nodiscard]] bool isValidOpcode() const noexcept;         // Checks if the opcode input is valid
private:
    unsigned char* m_encode{ nullptr }; // Pointer to the encoded bytes
    ks_engine* m_ks{ nullptr };
    ks_arch m_arch{ KS_ARCH_X86 };
    ks_mode m_mode{ KS_MODE_32 };

    std::string m_opcode;
};

#endif // ASSEMBLER_HPP