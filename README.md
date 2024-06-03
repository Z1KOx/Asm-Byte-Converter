### This project allows you to input your assembly code (opcode) directly into the console.

# How does this work?

### 1. Write your opcode
Open the executable file and input your assembly code. For example:
```bash
Enter your opcode
>  inc dword ptr ds:[esi]
```

### 2. Display result
The project will then display the bytes of your entered assembly code. For example:
```bash
Opcode [ inc dword ptr ds:[esi] ]
|
+------> Bytes [ FF 06 ]
         |
         +-----> Binaries [ 1111 1111 0000 0110 ]
                          [ F    F    0    6    ]
```

## To clone this project with Git
```bash
git clone https://github.com/Z1KOx/OpcodeToBytes.git
```
