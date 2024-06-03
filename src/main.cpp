#include "include/Assembler.hpp"

#include <iostream>

int main()
{
    try
    {
        Assembler assembler;
        assembler.getUserOpcode();
        assembler.print();
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
    }

    std::cin.get();
    return 0;
}