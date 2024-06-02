#include "include/Assembler.hpp"
#include <iostream>

int main()
{
    std::string opcodeInput;

    std::puts("Enter your opcode");
    std::getline(std::cin >> std::ws, opcodeInput);
    std::cout << '\n';

    try
    {
        Assembler assembler;
        assembler.printBytes(opcodeInput);
    }
    catch(std::exception& ex) {
        std::puts(ex.what());
    }
    
    std::cin.get();
    return 0;
}