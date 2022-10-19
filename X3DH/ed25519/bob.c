#include<stdio.h>
#include "src/ed25519.h"
#include<string.h>
#include "../rfc6234/sha.h"

/**
 * This file is for Bob in the X3DH protocol
 * This file does the following:
 * 1. Generate a long-term identity key pair ID_b
 * 2. Generate a Signed Prekey for Bob 
 * 3. Generate Bob's Signed prekey signature Sig(IK_b, Encode(SPK_b))
 * 4. Send to Server the public keys
 * 5. Wait for Alice to verify and receives IK_a, EK_a, ciphertext encrypted with SK
 * 6. Verify signature and calculate SK 
 * 7. Decrypt the initialcipher text with SK 
 * https://github.com/massar/rfc6234/blob/master/hkdf.c
 * https://www.reddit.com/r/cryptography/comments/q8r2ld/x3dh_what_does_it_provide_and_why_is_it_more/
 * https://github.com/PaulLaux/X3DH-Key-Exchange/blob/master/x3dh.cpp
 */


void SendtoServer(const unsigned char *id_public_key, unsigned char *spk_public_key, const unsigned char *spk_signature){};

void ReceiveFromAlice(unsigned char *alice_identity_public_key, unsigned char *alice_ephemeral_public_key, unsigned char *initial_ciphertext){};

void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt_len, const unsigned char *info,
                    unsigned char* output_key, int okm_len);

void get_dh_output(unsigned char* alice_identity_public_key, unsigned char* spk_private_key, unsigned char* id_private_key, 
                    unsigned char* alice_ephemeral_public_key, unsigned char* dh_final);

int main() {
    unsigned char id_public_key[32]; //Bob's Identity Public Key
    unsigned char id_private_key[64]; //Bob's Identity Private Key
    unsigned char seed[32]; //Seed to generate new keys
    unsigned char scalar[32]; //Scalar to add to modify key
    unsigned char spk_public_key[32]; //Bob's Signed prekey public
    unsigned char spk_private_key[64]; //Bob's Signed prekey private
    unsigned char spk_signature[64]; //Bob's Signed prekey signature
    unsigned char alice_identity_public_key[32]; //Alice public identity key
    unsigned char alice_ephemeral_public_key[32]; //Alice ephemeral/generated key
    const unsigned char shared_key_hash[128]; //Shared key hashed
    unsigned char dh_final[96];
    unsigned char ad[32];

    unsigned char hex_hkdf_output[128]; 

    //Generating long-term Identity Key pair for Bob
    ed25519_create_seed(seed); //create randome seed
    ed25519_create_keypair(id_public_key, id_private_key, seed); //create keypair out of seed 

    //Generate SignedPreKey Pair for bob
    ed25519_create_seed(seed); //create random seed 
    ed25519_create_keypair(spk_public_key, spk_private_key, seed); //create keypair out of seed

    //TODO: Will need to remove the message and message_len from this function. As of now keeping it. 
    ed25519_sign(spk_signature, id_public_key, id_private_key);

    //Send to Server:
    SendtoServer(id_public_key,spk_public_key,spk_signature);

    /**
     * WAIT TO RECEIVE KEYS FROM ALICE
     */

    //IF KEYS being sent from Alice
    // ReceiveFromAlice(alice_identity_public_key, alice_ephemeral_public_key, shared_key_hash);
    get_dh_output(alice_identity_public_key, spk_private_key, id_private_key,alice_ephemeral_public_key, dh_final);
    get_shared_key(dh_final, SHA512, NULL, NULL, hex_hkdf_output, 128);

    //TODO: Maybe Construct AD 
    //TODO: HKDF
    // https://stackoverflow.com/questions/19147619/what-implementions-of-ed25519-exist - as per this link this code needs to hash the keys before sending


    return 0;
}

void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt, const unsigned char *info,
     unsigned char* output_key, int okm_len){
    int salt_len; //The length of the salt value (a non-secret random value) (ignored if SALT==NULL)
    int info_len; // The length of optional context and application (ignored if info==NULL)
    int ikm_len; //The length of the input keying material
    uint8_t okm_integer[okm_len];
    ikm_len = 96;
    printf("%d\n", ikm_len);
    if(salt == NULL) salt_len = 0;
    if(info == NULL) info_len = 0;



    if(hkdf(whichSha,salt,salt_len,dh_final,ikm_len,info,info_len,okm_integer,okm_len) == 0)
    {
        printf("HKDF is valid\n");
    } else {
        fprintf(stderr, "HKDF is invalid\n");
    }

    for(int i=0; i<okm_len;i++)
    {
        output_key[i] = okm_integer[i];
        printf("%d\n", output_key[i]);
    }

}

void get_dh_output(unsigned char* alice_identity_public_key, unsigned char* spk_private_key, unsigned char* id_private_key, 
                    unsigned char* alice_ephemeral_public_key, unsigned char* dh_final)
{
    //DH outputs
    unsigned char dh1[32], dh2[32], dh3[32]; //DH exchanges - no opk so only 3 outputs

    //DH1 = DH(IKA, SPKB)
    ed25519_key_exchange(dh1, alice_identity_public_key, spk_private_key);

    //DH2 = DH(EKA, IKB)
    ed25519_key_exchange(dh2, alice_ephemeral_public_key, id_private_key);

    //DH3 = DH(EKA, SPKB)
    ed25519_key_exchange(dh3, alice_ephemeral_public_key, spk_private_key);

    //Concatenating dh outputs
    strcat(dh_final, dh1);
    strcat(dh_final, dh2);
    strcat(dh_final, dh3);
}
