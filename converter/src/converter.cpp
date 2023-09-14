#include <iostream>
#include <fstream>

#include <capstone//capstone.h>

uint8_t *CODE = (uint8_t *) "\x55\x48\x8b\x05\xb8\x13\x00\x00";

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: ./converter <X86_64 file> <AARCH64 result file> \n";
        return 1;
    }

    std::ifstream aarch64_file(argv[1]);

    if (!aarch64_file.is_open()) {
        std::cerr << "Failed to open file." << std::endl;
        return 1;
    }

    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;
    auto x = reinterpret_cast<uint8_t *>(CODE);
    count = cs_disasm(handle, CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                   insn[j].op_str);
        }

        cs_free(insn, count);
    } else
        printf("ERROR: Failed to disassemble given code!\n");

    cs_close(&handle);

    std::cout << "Hello, World!" << std::endl;
    return 0;
}
