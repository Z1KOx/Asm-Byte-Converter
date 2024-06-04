#include "include/Assembler.hpp"

#include <iostream>
#include <iomanip>
#include <bitset>

// Constructor: Initializes the Keystone engine with x86 architecture
Assembler::Assembler() noexcept
{
	if (ks_open(m_arch, m_mode, &m_ks) != KS_ERR_OK) {
		std::cerr << "Failed to initialize keystone";
		return;
	}
}

// Destructor: Closes the Keystone engine and frees allocated memory
Assembler::~Assembler() noexcept
{
	if (m_ks) {
		ks_close(m_ks);
	}
}

// Prompts the user to enter an opcode and validates it
void Assembler::getUserOpcode() noexcept
{
	std::puts("Enter your opcode");
	std::cout << ">  ";

	while (true)
	{
		std::getline(std::cin >> std::ws, m_opcode);

		if (!isValidOpcode())
		{
			std::puts("Invalid opcode entered");
			std::cout << ">  ";
			continue;
		}

		break;
	}

	system("cls");
}

// Prints the opcode, its bytes, and their binary representation
void Assembler::print() const noexcept
{
	std::cout << "Opcode [ " << m_opcode << " ]\n"
		<< "|\n"
		<< "+------> ";

	const auto bytes = assemble();
	if (!bytes.empty())
	{
		printBytes(bytes);
		printBinaries(bytes);

		std::cout << '\n';
	}
	else {
		std::cerr << "Failed to assemble the given opcode or no bytes generated.";
	}
}

// Handles the user's choice to input another opcode or exit the program
[[nodiscard]] bool Assembler::handleUserChoice() const noexcept
{
	auto input{ 0 };
	std::puts("\n1] To input another opcode\n2] To exit the program");
	std::cout << ">  ";

	while (true)
	{
		std::cin >> input;

		switch (input)
		{
		case 1: return false;
		case 2: return true;
		default:
			std::cin.clear();
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

			std::puts("Invalid input");
			std::cout << ">  ";
		}
	}
}

// Prints the bytes in hexadecimal format
void Assembler::printBytes(const std::vector<unsigned char>& bytes) const noexcept
{
	std::cout << "Bytes [ ";

	for (const auto& byte : bytes)
	{
		std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
		if (&byte != &bytes.back()) {
			std::cout << ' ';
		}
	}
	std::cout << " ]\n"
		<< "         |\n"
		<< "         +-----> ";
}


// Prints the bytes in binary format
void Assembler::printBinaries(const std::vector<unsigned char>& bytes) const noexcept
{
	std::cout << "Binaries [ ";
	auto count{ 0 };
	for (const auto& byte : bytes)
	{
		std::bitset<8> bits(byte);
		for (auto i{ 7 }; i >= 0; --i)
		{
			std::cout << bits[i];
			count++;
			if (count % 4 == 0) {
				std::cout << ' ';
			}
		}
	}
	std::cout << "]\n";

	// Hex byte print
	std::cout << "                          [ ";
	for (const auto& byte : bytes) {
		std::cout << std::hex << std::uppercase << std::setw(1) << std::setfill(' ') << static_cast<int>(byte) / 16 << "    ";
		std::cout << std::hex << std::uppercase << std::setw(1) << std::setfill(' ') << static_cast<int>(byte) % 16 << "    ";
	}
	std::cout << ']';
}


// Assembles the opcode into bytes using the Keystone engine
[[nodiscard]] std::vector<unsigned char> Assembler::assemble() const noexcept
{
	std::vector<unsigned char> bytes;

	size_t size, count;
	unsigned char* encode{ nullptr };
	const auto err = static_cast<ks_err>(ks_asm(m_ks, m_opcode.c_str(), 0, &encode, &size, &count));
	if (err != KS_ERR_OK) {
		std::cerr << "Failed to assemble";
		return bytes;
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
	const auto err = ks_asm(ks, m_opcode.c_str(), 0, &encode, &size, &count);

	ks_close(ks);

	if (err != KS_ERR_OK) {
		return false;
	}

	ks_free(encode);
	return true;
}
