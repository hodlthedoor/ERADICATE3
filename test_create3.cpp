#include <iostream>
#include <iomanip>
#include "sha3.hpp"
#include "types.hpp"

void print_hex(const unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)data[i];
    }
}

int main() {
    // Test CREATE3 with salt = 0x0000000000000000000000000000000000000000000000000000000000000001
    // Expected result: 0xa87c98D096C7076064d26D17f420368098CC9717

    // Step 1: Calculate proxy address
    ethhash h_proxy = { 0 };
    h_proxy.b[0] = 0xff;

    // Factory: 0xBA203fFDB6727c59e31D73d66290fFb47728e4Cb
    h_proxy.b[1] = 0xBA; h_proxy.b[2] = 0x20; h_proxy.b[3] = 0x3f; h_proxy.b[4] = 0xFD;
    h_proxy.b[5] = 0xB6; h_proxy.b[6] = 0x72; h_proxy.b[7] = 0x7c; h_proxy.b[8] = 0x59;
    h_proxy.b[9] = 0xe3; h_proxy.b[10] = 0x1D; h_proxy.b[11] = 0x73; h_proxy.b[12] = 0xd6;
    h_proxy.b[13] = 0x62; h_proxy.b[14] = 0x90; h_proxy.b[15] = 0xFF; h_proxy.b[16] = 0xb4;
    h_proxy.b[17] = 0x77; h_proxy.b[18] = 0x28; h_proxy.b[19] = 0xe4; h_proxy.b[20] = 0xCb;

    // Salt: 0x0000000000000000000000000000000000000000000000000000000000000001
    for (int i = 0; i < 31; i++) {
        h_proxy.b[21 + i] = 0x00;
    }
    h_proxy.b[52] = 0x01;

    // PROXY_INITCODE_HASH: 0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f
    h_proxy.b[53] = 0x21; h_proxy.b[54] = 0xc3; h_proxy.b[55] = 0x5d; h_proxy.b[56] = 0xbe;
    h_proxy.b[57] = 0x1b; h_proxy.b[58] = 0x34; h_proxy.b[59] = 0x4a; h_proxy.b[60] = 0x24;
    h_proxy.b[61] = 0x88; h_proxy.b[62] = 0xcf; h_proxy.b[63] = 0x33; h_proxy.b[64] = 0x21;
    h_proxy.b[65] = 0xd6; h_proxy.b[66] = 0xce; h_proxy.b[67] = 0x54; h_proxy.b[68] = 0x2f;
    h_proxy.b[69] = 0x8e; h_proxy.b[70] = 0x9f; h_proxy.b[71] = 0x30; h_proxy.b[72] = 0x55;
    h_proxy.b[73] = 0x44; h_proxy.b[74] = 0xff; h_proxy.b[75] = 0x09; h_proxy.b[76] = 0xe4;
    h_proxy.b[77] = 0x99; h_proxy.b[78] = 0x3a; h_proxy.b[79] = 0x62; h_proxy.b[80] = 0x31;
    h_proxy.b[81] = 0x9a; h_proxy.b[82] = 0x49; h_proxy.b[83] = 0x7c; h_proxy.b[84] = 0x1f;

    // Hash step 1 - Solady hashes exactly 85 bytes (0x55)
    char step1_result[32];
    sha3((char*)h_proxy.b, 85, step1_result, 32);

    std::cout << "Step 1 input (first 85 bytes): 0x";
    print_hex(h_proxy.b, 85);
    std::cout << std::endl;

    std::cout << "Step 1 proxy hash: 0x";
    print_hex((unsigned char*)step1_result, 32);
    std::cout << std::endl;

    std::cout << "Proxy address: 0x";
    print_hex((unsigned char*)step1_result + 12, 20);
    std::cout << std::endl;

    // Step 2: Final address - match Solady's memory layout
    ethhash h_final = { 0 };

    // Solady memory layout:
    // 0x00: 0xd694 (but hash starts at 0x1e=30)
    // 0x14: proxy address (20 bytes)
    // 0x34: 0x01 (nonce)
    // Hash from 0x1e for 0x17 bytes

    h_final.b[30] = 0xd6;  // 0x1e position
    h_final.b[31] = 0x94;  // 0x1f position
    // Copy proxy address to positions 32-51 (0x20-0x33)
    for (int i = 0; i < 20; i++) {
        h_final.b[32 + i] = step1_result[12 + i];
    }
    h_final.b[52] = 0x01;  // 0x34 position

    char final_result[32];
    sha3((char*)&h_final.b[30], 23, final_result, 32);

    std::cout << "Step 2 input (from offset 30): 0x";
    print_hex(&h_final.b[30], 23);
    std::cout << std::endl;

    std::cout << "Final address: 0x";
    print_hex((unsigned char*)final_result + 12, 20);
    std::cout << std::endl;

    return 0;
}