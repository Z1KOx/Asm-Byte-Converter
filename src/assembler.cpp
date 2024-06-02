#include "include/Assembler.hpp"
#include <iostream>
#include <iomanip>

Assembler::Assembler(const ks_arch arch, const ks_mode mode)
    : m_ks(nullptr), m_arch(arch), m_mode(mode)
{
    if (ks_open(m_arch, m_mode, &m_ks) != KS_ERR_OK)
    {
        std::puts("ERROR: failed to initialize keystone engine!");
        m_ks = nullptr;
    }
}

Assembler::~Assembler() noexcept
{
    if (m_ks)
        ks_close(m_ks);
    if(m_encode)
        ks_free(m_encode);
}

std::vector<unsigned char> Assembler::assemble(const std::string& assemblyCode) noexcept
{
    std::vector<unsigned char> byteCode;
    if (!m_ks)
        return byteCode;

    size_t size, count;
	const auto err = static_cast<ks_err>(ks_asm(m_ks, assemblyCode.c_str(), 0, &m_encode, &size, &count));
    if (err != KS_ERR_OK)
    {
        std::cerr << "ERROR: failed to assemble given code! (error code: " << err << ")\n";
        std::cerr << "Error message: " << ks_strerror(err) << '\n';
        return byteCode;
    }

    byteCode.assign(m_encode, m_encode + size);

    return byteCode;
}

void Assembler::printBytes(const std::string& assemblyCode) noexcept
{
    const std::vector<unsigned char> byteCode = assemble(assemblyCode);
    if (!byteCode.empty())
    {
        std::cout << "Bytes: ";
        for (const auto& byte : byteCode) {
	        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }

        std::cout << std::dec << '\n';
    }
    else
        std::puts("Failed to assemble the given opcode or no bytes generated.");
}