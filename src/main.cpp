#include "include/Assembler.hpp"

#include <iostream>

int main()
{
    try
    {
        Assembler assembler;
        assembler.getUsersOpcode();
        assembler.printBytes();
    }
    catch(std::exception& ex) {
        std::puts(ex.what());
    }
    
    std::cin.get();
    return 0;
}