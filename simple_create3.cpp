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
    // Simple CREATE3 = CREATE2 + CREATE
    // Test with salt: 0x5bdaa4327a3f941bf928b57a80c94931e500b653ca82273b7bfad8045d85a470
    // Expected from ERADICATE3: 0x075fbf3091bcca5b88b45882d0fc3f9596433a6b

    unsigned char create2_input[85];

    // Step 1: CREATE2 proxy address calculation
    // keccak256(0xff ++ factory ++ salt ++ proxy_initcode_hash)

    // 0xff
    create2_input[0] = 0xff;

    // Factory: 0xBA203fFDB6727c59e31D73d66290fFb47728e4Cb
    create2_input[1] = 0xBA; create2_input[2] = 0x20; create2_input[3] = 0x3f; create2_input[4] = 0xFD;
    create2_input[5] = 0xB6; create2_input[6] = 0x72; create2_input[7] = 0x7c; create2_input[8] = 0x59;
    create2_input[9] = 0xe3; create2_input[10] = 0x1D; create2_input[11] = 0x73; create2_input[12] = 0xd6;
    create2_input[13] = 0x62; create2_input[14] = 0x90; create2_input[15] = 0xFF; create2_input[16] = 0xb4;
    create2_input[17] = 0x77; create2_input[18] = 0x28; create2_input[19] = 0xe4; create2_input[20] = 0xCb;

    // Salt: 0x48ed14aa5bb9c4aa970d08638b3aa4e4e500b653ca82273b7bfad8045d85a470
    create2_input[21] = 0x48; create2_input[22] = 0xed; create2_input[23] = 0x14; create2_input[24] = 0xaa;
    create2_input[25] = 0x5b; create2_input[26] = 0xb9; create2_input[27] = 0xc4; create2_input[28] = 0xaa;
    create2_input[29] = 0x97; create2_input[30] = 0x0d; create2_input[31] = 0x08; create2_input[32] = 0x63;
    create2_input[33] = 0x8b; create2_input[34] = 0x3a; create2_input[35] = 0xa4; create2_input[36] = 0xe4;
    create2_input[37] = 0xe5; create2_input[38] = 0x00; create2_input[39] = 0xb6; create2_input[40] = 0x53;
    create2_input[41] = 0xca; create2_input[42] = 0x82; create2_input[43] = 0x27; create2_input[44] = 0x3b;
    create2_input[45] = 0x7b; create2_input[46] = 0xfa; create2_input[47] = 0xd8; create2_input[48] = 0x04;
    create2_input[49] = 0x5d; create2_input[50] = 0x85; create2_input[51] = 0xa4; create2_input[52] = 0x70;

    // Proxy initcode hash
    create2_input[53] = 0x21; create2_input[54] = 0xc3; create2_input[55] = 0x5d; create2_input[56] = 0xbe;
    create2_input[57] = 0x1b; create2_input[58] = 0x34; create2_input[59] = 0x4a; create2_input[60] = 0x24;
    create2_input[61] = 0x88; create2_input[62] = 0xcf; create2_input[63] = 0x33; create2_input[64] = 0x21;
    create2_input[65] = 0xd6; create2_input[66] = 0xce; create2_input[67] = 0x54; create2_input[68] = 0x2f;
    create2_input[69] = 0x8e; create2_input[70] = 0x9f; create2_input[71] = 0x30; create2_input[72] = 0x55;
    create2_input[73] = 0x44; create2_input[74] = 0xff; create2_input[75] = 0x09; create2_input[76] = 0xe4;
    create2_input[77] = 0x99; create2_input[78] = 0x3a; create2_input[79] = 0x62; create2_input[80] = 0x31;
    create2_input[81] = 0x9a; create2_input[82] = 0x49; create2_input[83] = 0x7c; create2_input[84] = 0x1f;

    std::cout << "CREATE2 input: 0x";
    print_hex(create2_input, 85);
    std::cout << std::endl;

    char proxy_hash[32];
    sha3((char*)create2_input, 85, proxy_hash, 32);

    std::cout << "Proxy hash: 0x";
    print_hex((unsigned char*)proxy_hash, 32);
    std::cout << std::endl;

    std::cout << "Proxy address: 0x";
    print_hex((unsigned char*)&proxy_hash[12], 20);
    std::cout << std::endl;

    // Step 2: CREATE final address calculation
    // keccak256(rlp_encode(proxy_address, nonce=1))
    // RLP(address, 1) = 0xd6 0x94 <20_byte_address> 0x01

    unsigned char create_input[23];
    create_input[0] = 0xd6;  // RLP list with 22 bytes following
    create_input[1] = 0x94;  // RLP address with 20 bytes following

    // Copy proxy address
    memcpy(&create_input[2], &proxy_hash[12], 20);

    create_input[22] = 0x01; // nonce = 1

    std::cout << "CREATE input: 0x";
    print_hex(create_input, 23);
    std::cout << std::endl;

    char final_hash[32];
    sha3((char*)create_input, 23, final_hash, 32);

    std::cout << "Final address: 0x";
    print_hex((unsigned char*)&final_hash[12], 20);
    std::cout << std::endl;

    return 0;
}