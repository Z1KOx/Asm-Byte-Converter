# Asm-Byte-Converter
Convert your opcode into bytes and binary format.

> [!NOTE] 
> - It only works in x86 assembly.
> - This project has only been tested on the Windows operating system.
> - To build this project, you need to have CMake installed. You can install it <a href="https://cmake.org/download/">here</a>


# How does this work?

### 1. Write your opcode
Open the executable file and input your assembly code. For example:
```
Enter your opcode
>  inc dword ptr ds:[esi]
```

### 2. Display result
The executable will then display the bytes of your entered assembly code. For example:
```
Opcode [ inc dword ptr ds:[esi] ]
|
+------> Bytes [ FF 06 ]
         |
         +-----> Binaries [ 1111 1111 0000 0110 ]
                          [ F    F    0    6    ]
```

# Getting Started
### 1. Clone this project using Git
```bash
git clone https://github.com/Z1KOx/Asm-Byte-Converter.git
```
- If you don't have Git installed, you can download it <a href="https://git-scm.com/downloads">here</a>

### 2. Run build.bat
This will compile and link the executable, and it will provide you with the path where the executable file is located.

> [!NOTE]
> Ensure the keystone.dll is in the same directory before opening the executable file.
