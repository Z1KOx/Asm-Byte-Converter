> [!NOTE] 
> - While this implementation has been thoroughly tested with x86 assembly, compatibility with x64 assembly may not be guaranteed.
> - This project has only been tested on the Windows operating system.

# Overview
Run the executable and input your assembly code. For example:

# How does this work?

### 1. Write your opcode
Open the executable file and input your assembly code. For example:
```bash
Enter your opcode
>  inc dword ptr ds:[esi]
```

### 2. Display result
The executable will then display the bytes of your entered assembly code. For example:
```bash
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
This will compile and link the executable, and it will provide you with the path where the .exe file is located.

> [!NOTE]
> Ensure the keystone.dll is in the same directory before opening the .exe file.
