#include "include/Assembler.hpp"

#include <iostream>
#include <iomanip>
#include <bitset>

// Constructor: Initializes the Keystone engine with x86 architecture
Assembler::Assembler()
{
	if (ks_open(m_arch, m_mode, &m_ks) != KS_ERR_OK) {
		throw std::runtime_error("Failed to initialize keystone");
	}
}

// Destructor: Closes the Keystone engine and frees allocated memory
Assembler::~Assembler() noexcept
{
	if (m_ks) {
		ks_close(m_ks);
	}
	if (m_encode) {
		ks_free(m_encode);
	}
}

// Prompts the user to enter an opcode and validates it
void Assembler::getUserOpcode()
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

// Prints the opcode, its bytes, and their binary representation
void Assembler::print()
{
	std::cout << "Opcode:   " << m_opcode << '\n';

	const std::vector<unsigned char> bytes = assemble();
	if (!bytes.empty()) 
	{
		printBytes(bytes);
		std::cout << '\n';
		printBinaries(bytes);

		std::cout << '\n';
	}
	else {
		throw std::runtime_error("Failed to assemble the given opcode or no bytes generated.");
	}
}


// Prints the bytes in hexadecimal format
void Assembler::printBytes(const std::vector<unsigned char>& bytes) const noexcept
{
	std::cout << "Bytes:    ";
	for (const auto& byte : bytes) {
		std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
	}
}

// Prints the bytes in binary format
void Assembler::printBinaries(const std::vector<unsigned char>& bytes) const noexcept
{
	std::cout << "Binaries: ";
	for (const auto& byte : bytes) {
		std::cout << std::bitset<8>(byte) << ' ';
	}
}

// Assembles the opcode into bytes using the Keystone engine
[[nodiscard]] std::vector<unsigned char> Assembler::assemble() const
{
	std::vector<unsigned char> bytes;

	size_t size, count;
	unsigned char* encode{ nullptr };
	const auto err = static_cast<ks_err>(ks_asm(m_ks, m_opcode.c_str(), 0, &encode, &size, &count));
	if (err != KS_ERR_OK) {
		throw std::runtime_error("Failed to assemble");
	}

	bytes.assign(encode, encode + size);
	ks_free(encode);

	return bytes;
}

// Validates the opcode by attempting to assemble it using a temporary Keystone engine instance
[[nodiscard]] bool Assembler::isValidOpcode() const noexcept
{
	ks_engine* ks;
	if (ks_open(KS_ARCH_X86, KS_MODE_32, &ks) != KS_ERR_OK) {
		return false;
	}

	size_t size, count;
	unsigned char* encode = nullptr;
	const int err = ks_asm(ks, m_opcode.c_str(), 0, &encode, &size, &count);

	ks_close(ks);

	if (err != KS_ERR_OK) {
		return false;
	}

	ks_free(encode);
	return true;
}