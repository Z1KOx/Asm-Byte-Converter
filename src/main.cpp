#include "include/Assembler.hpp"
#include <iostream>

int main()
{
    Assembler assembler;
    std::string opcodeInput;

    std::puts("Enter your opcode");
    std::getline(std::cin >> std::ws, opcodeInput);
    std::cout << '\n';

    assembler.printBytes(opcodeInput);

    std::cin.get();
    return 0;
}