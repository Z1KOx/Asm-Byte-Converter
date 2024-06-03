#include <bitset>

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
	if (m_encode)
		ks_free(m_encode);
}

void Assembler::printBytes()
{
	std::cout << "Opcode   " << m_opcode << '\n';

	const std::vector<unsigned char> bytes = assemble();
	if (!bytes.empty())
	{
		std::cout << "Bytes    ";
		for (const auto& byte : bytes) {
			std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
		}

		printBinaries(bytes);

		std::cout << std::dec << std::nouppercase << '\n';
	}
	else
		throw std::runtime_error("Failed to assemble the given opcode or no bytes generated.");
}

void Assembler::getUsersOpcode()
{
	std::puts("Enter your opcode");

	while (true)
	{
		std::getline(std::cin >> std::ws, m_opcode);

		if (!isValidOpcode())
		{
			std::puts("Invalid opcode entered");
			continue;
		}

		break;
	}

	system("cls");
}

void Assembler::printBinaries(const std::vector<unsigned char>& bytes) const noexcept
{
	std::cout << "\nBinaries ";
	for (const auto& byte : bytes) {
		std::cout << std::bitset<8>(byte) << ' ';
	}
}

[[nodiscard]] std::vector<unsigned char> Assembler::assemble()
{
	std::vector<unsigned char> bytes;

	size_t size, count;
	const auto err = static_cast<ks_err>(ks_asm(m_ks, m_opcode.c_str(), 0, &m_encode, &size, &count));
	if (err != KS_ERR_OK)
		throw std::runtime_error("Failed to assemble");

	bytes.assign(m_encode, m_encode + size);

	return bytes;
}

[[nodiscard]] bool Assembler::isValidOpcode() const noexcept
{
	ks_engine* ks;

	if (ks_open(KS_ARCH_X86, KS_MODE_32, &ks) != KS_ERR_OK)
		return false;

	size_t size, count;
	unsigned char* encode;
	const int err = ks_asm(ks, m_opcode.c_str(), 0, &encode, &size, &count);

	ks_close(ks);

	if (err != KS_ERR_OK)
		return false;

	ks_free(encode);
	return true;
}