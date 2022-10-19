#include<stdio.h>
// #include "src/ed25519.h"

/**
 * This code is for the Sony Spresence board 
 * The server is going to send to Alice, Bob's Prekey Bundle. 
 * 
 * Thie file will have the following: 
 * 1. Encoding Function to encode the public key before sending - Encode()
 * 2. Bob's Identity Key (long-term Public Key) IK_b
 * 3. Bob's Signed Prekey (SPK_b)
 * 4. Bob's prekey signature Sig(IK_b, Encode(SPK_b))
 * https://crypto.stackexchange.com/questions/52976/x3dh-protocol-how-can-the-receiver-calculate-the-shared-key
 * https://betterexplained.com/articles/understanding-big-and-little-endian-byte-order/
 */



void ReceiveFromBob(unsigned char *id_public_key, unsigned char *spk_public_key, unsigned char *spk_signature){};

void SendToAlice(unsigned char *id_public_key, unsigned char *spk_public_key, unsigned char *spk_signature){};

int main(){
    //Defining Bob's public key, Bob's
    unsigned char id_public_key[32];
    unsigned char spk_public_key[32];
    unsigned char spk_signature[64];
    ReceiveFromBob(id_public_key, spk_public_key, spk_signature);
    SendToAlice(id_public_key, spk_public_key, spk_signature);
}
 