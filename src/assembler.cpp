#include "include/Assembler.hpp"
#include <iostream>
#include <iomanip>

Assembler::Assembler()
    : m_ks(nullptr), m_arch(KS_ARCH_X86), m_mode(KS_MODE_32)
{
    if (ks_open(m_arch, m_mode, &m_ks) != KS_ERR_OK)
	    throw std::runtime_error("Failed to initialize keystone");
}

Assembler::~Assembler() noexcept
{
    if (m_ks)
        ks_close(m_ks);
    if(m_encode)
        ks_free(m_encode);
}

std::vector<unsigned char> Assembler::assemble(const std::string& assemblyCode)
{
    std::vector<unsigned char> bytes;

    size_t size, count;
	const auto err = static_cast<ks_err>(ks_asm(m_ks, assemblyCode.c_str(), 0, &m_encode, &size, &count));
	if (err != KS_ERR_OK)
        throw std::runtime_error("Failed to assemble");

    bytes.assign(m_encode, m_encode + size);

    return bytes;
}

void Assembler::printBytes(const std::string& assemblyCode) noexcept
{
    const std::vector<unsigned char> bytes = assemble(assemblyCode);
    if (!bytes.empty())
    {
        std::cout << "Bytes: ";
        for (const auto& byte : bytes) {
	        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }

        std::cout << std::dec << std::nouppercase << '\n';
    }
    else
        std::puts("Failed to assemble the given opcode or no bytes generated.");
}