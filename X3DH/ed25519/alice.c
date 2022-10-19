#include<stdio.h>
#include "src/ed25519.h"
#include<string.h>
#include "../rfc6234/sha.h"

// /**
//  * This file is for Alice in the X3DH protocol
//  * This file does the following:
//  * 1. Create long-term identity key pair for Alice
//  * 1. Fetch Prekey Bundle
//  * 2. Generate a long-term identity key pair ID_a
//  * 3. Verify signature of Bob's 
//  * 4. Generate Ephemeral Key Pair EK_a
//  * 5. Calculate SK 
//  * 6. Encrypt message with SK 
//  */

// unsigned char FetchPreKeyBundle(unsigned char *bob_id_public_key, unsigned char *bob_spk_public_key, unsigned char *bob_spk_signature){};
void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt_len, const unsigned char *info,
                    unsigned char* output_key, int okm_len);

void get_dh_output(unsigned char* bob_id_public_key, unsigned char* ephemeral_private_key, unsigned char* id_private_key, 
                    unsigned char* bob_spk_public_key, unsigned char* dh_final);

int main() {
    unsigned char bob_id_public_key[32];// bob's identity key
    unsigned char bob_spk_public_key[32];// bob's signed prekey
    unsigned char bob_spk_signature[64];// bob's signed prekey signature
    unsigned char id_public_key[32];//alice identity public key
    unsigned char id_private_key[64]; //alice identity private key
    unsigned char seed[32];  //Seed to generate new keys
    unsigned char scalar[32];//Scalar to add to modify key
    unsigned char ephemeral_public_key[32];
    unsigned char ephemeral_private_key[64]; 
    const unsigned char message[] = "Hey Bob, this is Alice!";
    const int message_len = strlen((char*) message);
    unsigned char dh_final[96]; //To store the concatenation of the dh outputs
    unsigned char hex_hkdf_output[128];

    //Creating Long-term keypair for Alice 
    ed25519_create_seed(seed);
    ed25519_create_keypair(id_public_key, id_private_key, seed);

    // FetchPreKeyBundle(bob_id_public_key, bob_spk_public_key, bob_spk_signature);
    unsigned char bob_id_private_key[64];
    ed25519_create_seed(seed);
    ed25519_create_keypair(bob_id_public_key, bob_id_private_key, seed);
    ed25519_sign(bob_spk_signature, bob_id_public_key, bob_id_private_key);
    if (ed25519_verify(bob_spk_signature, bob_id_public_key)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
        // Abort();
    }

    ed25519_create_seed(seed);
    ed25519_create_keypair(ephemeral_private_key, ephemeral_public_key, seed);

    get_dh_output(bob_id_public_key, ephemeral_private_key, id_private_key, bob_spk_public_key, dh_final);
    get_shared_key(dh_final, SHA512, NULL, NULL, hex_hkdf_output, 128);
    //TODO: Maybe Construct AD as per the signal protocol (i.e. safety number)
    //TODO: HKDF
    //TODO: Encrypt with some aead encryption scheme (not sure which ones) 
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

void get_dh_output(unsigned char* bob_id_public_key, unsigned char* ephemeral_private_key, unsigned char* id_private_key, 
                    unsigned char* bob_spk_public_key, unsigned char* dh_final)
{
    //DH outputs
    unsigned char dh1[32], dh2[32], dh3[32]; //DH exchanges - no opk so only 3 outputs

    //DH1 = DH(IKA, SPKB)
    ed25519_key_exchange(dh1, bob_id_public_key, id_private_key);

    //DH2 = DH(EKA, IKB)
    ed25519_key_exchange(dh2, bob_id_public_key, ephemeral_private_key);

    //DH3 = DH(EKA, SPKB)
    ed25519_key_exchange(dh3, bob_spk_public_key, ephemeral_private_key);

    //Concatenating dh outputs
    strcat(dh_final, dh1);
    strcat(dh_final, dh2);
    strcat(dh_final, dh3);
}
