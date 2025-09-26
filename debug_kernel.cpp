#include <iostream>
#include <iomanip>
#include "sha3.hpp"

void print_hex(const unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)data[i];
    }
}

int main() {
    // Simulate exactly what the kernel does

    // Hardcoded salt that we know should work
    unsigned char original_salt[32] = {
        0x36, 0x06, 0x84, 0x18, 0x87, 0x3f, 0xe4, 0x94,
        0x9d, 0x24, 0x6a, 0x9a, 0x8b, 0xd3, 0xe4, 0x5d,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
    };

    // Step 1: CREATE2 proxy address calculation
    unsigned char h_create2[200] = {0};

    // Pack all 85 bytes into the structure
    h_create2[0] = 0xff;

    // Factory: 0xBA203fFDB6727c59e31D73d66290fFb47728e4Cb
    h_create2[1] = 0xBA; h_create2[2] = 0x20; h_create2[3] = 0x3f; h_create2[4] = 0xFD;
    h_create2[5] = 0xB6; h_create2[6] = 0x72; h_create2[7] = 0x7c; h_create2[8] = 0x59;
    h_create2[9] = 0xe3; h_create2[10] = 0x1D; h_create2[11] = 0x73; h_create2[12] = 0xd6;
    h_create2[13] = 0x62; h_create2[14] = 0x90; h_create2[15] = 0xFF; h_create2[16] = 0xb4;
    h_create2[17] = 0x77; h_create2[18] = 0x28; h_create2[19] = 0xe4; h_create2[20] = 0xCb;

    // Use original salt (32 bytes)
    for (int i = 0; i < 32; i++) {
        h_create2[21 + i] = original_salt[i];
    }

    // Proxy initcode hash (32 bytes)
    h_create2[53] = 0x21; h_create2[54] = 0xc3; h_create2[55] = 0x5d; h_create2[56] = 0xbe;
    h_create2[57] = 0x1b; h_create2[58] = 0x34; h_create2[59] = 0x4a; h_create2[60] = 0x24;
    h_create2[61] = 0x88; h_create2[62] = 0xcf; h_create2[63] = 0x33; h_create2[64] = 0x21;
    h_create2[65] = 0xd6; h_create2[66] = 0xce; h_create2[67] = 0x54; h_create2[68] = 0x2f;
    h_create2[69] = 0x8e; h_create2[70] = 0x9f; h_create2[71] = 0x30; h_create2[72] = 0x55;
    h_create2[73] = 0x44; h_create2[74] = 0xff; h_create2[75] = 0x09; h_create2[76] = 0xe4;
    h_create2[77] = 0x99; h_create2[78] = 0x3a; h_create2[79] = 0x62; h_create2[80] = 0x31;
    h_create2[81] = 0x9a; h_create2[82] = 0x49; h_create2[83] = 0x7c; h_create2[84] = 0x1f;

    // Apply Keccak-256 padding exactly like kernel does
    // Zero remaining bytes first (already done by initialization)
    // Apply padding: XOR 0x01 at message end, XOR 0x80 at rate boundary (136-1=135)
    h_create2[85] ^= 0x01;
    h_create2[135] ^= 0x80;

    std::cout << "CREATE2 input before hash: 0x";
    print_hex(h_create2, 85);
    std::cout << std::endl;

    // Hash it using our sha3 function - only hash the actual 85 bytes
    char proxy_hash[32];
    sha3((char*)h_create2, 85, proxy_hash, 32);

    std::cout << "Proxy hash: 0x";
    print_hex((unsigned char*)proxy_hash, 32);
    std::cout << std::endl;

    std::cout << "Proxy address: 0x";
    print_hex((unsigned char*)&proxy_hash[12], 20);
    std::cout << std::endl;

    // Step 2: CREATE final address calculation
    unsigned char h_create[200] = {0};
    h_create[0] = 0xd6;
    h_create[1] = 0x94;

    // Copy proxy address (last 20 bytes of CREATE2 result)
    for (int i = 0; i < 20; i++) {
        h_create[2 + i] = proxy_hash[12 + i];
    }
    h_create[22] = 0x01;

    // Apply Keccak-256 padding for 23-byte input
    h_create[23] ^= 0x01;
    h_create[135] ^= 0x80;

    std::cout << "CREATE input before hash: 0x";
    print_hex(h_create, 23);
    std::cout << std::endl;

    // Hash it and use as final result - only hash the actual 23 bytes
    char final_hash[32];
    sha3((char*)h_create, 23, final_hash, 32);

    std::cout << "Final address: 0x";
    print_hex((unsigned char*)&final_hash[12], 20);
    std::cout << std::endl;

    return 0;
}