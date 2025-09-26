#include <iostream>
#include <iomanip>
#include <cstring>
#include "sha3.hpp"

void print_hex(const unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)data[i];
    }
}

int main() {
    // Recreate exact Solady assembly with correct order
    unsigned char memory[256] = {0};

    // mstore(0x00, deployer) - Store deployer at 0x00
    // Factory: 0xBA203fFDB6727c59e31D73d66290fFb47728e4Cb
    memory[0x00] = 0xBA; memory[0x01] = 0x20; memory[0x02] = 0x3f; memory[0x03] = 0xFD;
    memory[0x04] = 0xB6; memory[0x05] = 0x72; memory[0x06] = 0x7c; memory[0x07] = 0x59;
    memory[0x08] = 0xe3; memory[0x09] = 0x1D; memory[0x0a] = 0x73; memory[0x0b] = 0xd6;
    memory[0x0c] = 0x62; memory[0x0d] = 0x90; memory[0x0e] = 0xFF; memory[0x0f] = 0xb4;
    memory[0x10] = 0x77; memory[0x11] = 0x28; memory[0x12] = 0xe4; memory[0x13] = 0xCb;

    // mstore8(0x0b, 0xff) - Store prefix, OVERWRITES byte at 0x0b
    memory[0x0b] = 0xff;

    // mstore(0x20, salt) - salt = 0x0000000000000000000000000000000000000000000000000000000000000001
    for (int i = 0; i < 31; i++) {
        memory[0x20 + i] = 0x00;
    }
    memory[0x3f] = 0x01;

    // mstore(0x40, PROXY_INITCODE_HASH)
    memory[0x40] = 0x21; memory[0x41] = 0xc3; memory[0x42] = 0x5d; memory[0x43] = 0xbe;
    memory[0x44] = 0x1b; memory[0x45] = 0x34; memory[0x46] = 0x4a; memory[0x47] = 0x24;
    memory[0x48] = 0x88; memory[0x49] = 0xcf; memory[0x4a] = 0x33; memory[0x4b] = 0x21;
    memory[0x4c] = 0xd6; memory[0x4d] = 0xce; memory[0x4e] = 0x54; memory[0x4f] = 0x2f;
    memory[0x50] = 0x8e; memory[0x51] = 0x9f; memory[0x52] = 0x30; memory[0x53] = 0x55;
    memory[0x54] = 0x44; memory[0x55] = 0xff; memory[0x56] = 0x09; memory[0x57] = 0xe4;
    memory[0x58] = 0x99; memory[0x59] = 0x3a; memory[0x5a] = 0x62; memory[0x5b] = 0x31;
    memory[0x5c] = 0x9a; memory[0x5d] = 0x49; memory[0x5e] = 0x7c; memory[0x5f] = 0x1f;

    std::cout << "Memory before proxy calculation:" << std::endl;
    std::cout << "0x00-0x13 (deployer after 0xff overwrite): 0x";
    print_hex(&memory[0x00], 0x14);
    std::cout << std::endl;
    std::cout << "0x0b-0x5f (proxy input): 0x";
    print_hex(&memory[0x0b], 0x55);
    std::cout << std::endl;

    // mstore(0x14, keccak256(0x0b, 0x55))
    char proxy_hash[32];
    sha3((char*)&memory[0x0b], 0x55, proxy_hash, 32);

    std::cout << "Proxy hash: 0x";
    print_hex((unsigned char*)proxy_hash, 32);
    std::cout << std::endl;

    // Store proxy address at 0x14
    memcpy(&memory[0x14], &proxy_hash[12], 20);

    std::cout << "Proxy address: 0x";
    print_hex(&memory[0x14], 20);
    std::cout << std::endl;

    // mstore(0x00, 0xd694) - This stores 0xd694 but we hash from 0x1e
    // So we need the right layout at 0x1e for the RLP: 0xd6 0x94 <proxy> 0x01
    memory[0x1e] = 0xd6;
    memory[0x1f] = 0x94;
    // Copy proxy address to 0x20-0x33
    memcpy(&memory[0x20], &proxy_hash[12], 20);
    // mstore8(0x34, 0x01)
    memory[0x34] = 0x01;

    std::cout << "Memory layout around final calculation:" << std::endl;
    std::cout << "0x00-0x02 (d694): 0x";
    print_hex(&memory[0x00], 3);
    std::cout << std::endl;
    std::cout << "0x14-0x27 (proxy addr): 0x";
    print_hex(&memory[0x14], 20);
    std::cout << std::endl;
    std::cout << "0x34 (nonce): 0x";
    print_hex(&memory[0x34], 1);
    std::cout << std::endl;
    std::cout << "Final input (0x1e-0x34): 0x";
    print_hex(&memory[0x1e], 0x17);
    std::cout << std::endl;

    // deployed := keccak256(0x1e, 0x17)
    char final_hash[32];
    sha3((char*)&memory[0x1e], 0x17, final_hash, 32);

    std::cout << "Final address: 0x";
    print_hex((unsigned char*)&final_hash[12], 20);
    std::cout << std::endl;

    return 0;
}