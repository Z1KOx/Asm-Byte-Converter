#include "include/Assembler.hpp"

#include <iostream>

int main()
{
    auto endLoop{ false };

    while (!endLoop)
    {
        Assembler assembler;
        assembler.getUserOpcode();
        assembler.print();
        endLoop = assembler.handleUserChoice();

        system("cls");
    }

	std::cin.get();
	return 0;
}