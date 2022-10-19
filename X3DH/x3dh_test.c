/*  Project:        Audio Encryption Project
    Description:    Element 14 Pi-Fest challenge submission. System comprised of three Raspberry Pi Picos 
                    named Bob, Alice, and Server. System securely sends audio between Bob and Alice using 
                    a lightweight cryptographic algorithm. Keys are exchanged using X3DH. Bob receives audio 
                    as input, encrypts it, and sends it to the server. Alice receives the message, decrypts
                    it, and plays the audio.
    Documentation:  https://github.com/lin0m/lightweight-cryptography
    Date:           Aug 9th, 2022
    School:         Cal Poly Pomona 
    Group:          Dr. Aly's Research Team
    Members:        Melvin Relf
                    Russell Hua
                    Alexander Ea
                    Shahzman Saqib
                    Muhammed Kamil
                    Patricia Ankunda
                    Lino Mercado-Esquivias
*/

#include<stdio.h>
#include "ed25519/src/ed25519.h"
#include "sha/rfc6234/sha.h"


void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt, const unsigned char *info,
     unsigned char* output_key, int okm_len);
int main()
{
    //Defining parameters for Bob
    unsigned char bob_id_public_key[32]; //Bob's Identity Public Key
    unsigned char bob_id_private_key[64]; //Bob's Identity Private Key
    unsigned char bob_seed[32]; //Seed to generate new keys
    unsigned char bob_spk_public_key[32]; //Bob's Signed prekey public
    unsigned char bob_spk_private_key[64]; //Bob's Signed prekey private
    unsigned char dh_final_bob[96];
    unsigned char hex_hkdf_output_bob[128];

    //Defining parameters for Alice
    unsigned char alice_id_public_key[32]; //Bob's Identity Public Key
    unsigned char alice_id_private_key[64]; //Bob's Identity Private Key
    unsigned char alice_seed[32]; //Seed to generate new keys
    unsigned char alice_ephemeral_public_key[32]; //Alice public identity key
    unsigned char alice_ephemeral_private_key[64]; //Alice ephemeral/generated key
    unsigned char dh_final_alice[96];
    unsigned char hex_hkdf_output_alice[128]; 
    unsigned char bob_spk_signature[64];

    //Generating long-term Identity Key pair for Bob
    ed25519_create_seed(bob_seed); //create randome seed
    ed25519_create_keypair(bob_id_public_key, bob_id_private_key, bob_seed); //create keypair out of seed 

    //Generate SignedPreKey Pair for bob
    ed25519_create_seed(bob_seed); //create random seed 
    ed25519_create_keypair(bob_spk_public_key, bob_spk_private_key, bob_seed); //create keypair out of seed

    ed25519_sign(bob_spk_signature, bob_id_public_key, bob_id_private_key);
    
    if (ed25519_verify(bob_spk_signature, bob_id_public_key)) {
        printf("\nvalid signature\n");
    } else {
        printf("\ninvalid signature\n");
        // Abort();
    }
    //Verifying on Alice's side
    ed25519_create_seed(alice_seed);
    ed25519_create_keypair(alice_id_public_key, alice_id_private_key, alice_seed);

    //Generate Ephemeral keys
    ed25519_create_seed(alice_seed);
    ed25519_create_keypair(alice_ephemeral_public_key, alice_ephemeral_private_key, alice_seed);

    //DH outputs for Alice
    unsigned char dh1_alice[32], dh2_alice[32], dh3_alice[32]; //DH exchanges - no opk so only 3 outputs
    unsigned char dh1_bob[32], dh2_bob[32], dh3_bob[32]; //DH exchanges - no opk so only 3 outputs

    //ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key)
    //DH1 = DH(IKA, SPKB)
    ed25519_key_exchange(dh1_alice, bob_spk_public_key, alice_id_private_key);

    //DH2 = DH(EKA, IKB) 
    ed25519_key_exchange(dh2_alice, bob_id_public_key, alice_ephemeral_private_key);

    //DH3 = DH(EKA, SPKB)
    ed25519_key_exchange(dh3_alice, bob_spk_public_key, alice_ephemeral_private_key);

    //  BOB'S KEY EXCHANGES
    //DH1 = DH(IKA, SPKB)
    ed25519_key_exchange(dh1_bob, alice_id_public_key, bob_spk_private_key);

    //DH2 = DH(EKA, IKB)
    ed25519_key_exchange(dh2_bob, alice_ephemeral_public_key, bob_id_private_key);

    //DH3 = DH(EKA, SPKB)
    ed25519_key_exchange(dh3_bob, alice_ephemeral_public_key, bob_spk_private_key);

    printf("Verifying dh1\n");
    for (int i = 0; i < 32; i++) {
            // printf("%d\t%d\n",dh1_alice[i], dh1_bob[i]);
            if (dh1_alice[i] != dh1_bob[i]) {
                printf("dh1 key exchange was incorrect\n");
                break;
            }
    }

    printf("Verifying dh2\n");
    for (int i = 0; i < 32; i++) {
        // printf("%d\t%d\n",dh2_alice[i], dh2_bob[i]);
        if (dh2_alice[i] != dh2_bob[i]) {
            printf("dh2 key exchange was incorrect\n");
            break;
        }
    }

    printf("Verifying dh3\n");
    for (int i = 0; i < 32; i++) {
        // printf("%d\t%d\n",dh3_alice[i], dh3_bob[i]);
        if (dh3_alice[i] != dh3_bob[i]) {
            printf("dh3 key exchange was incorrect\n");
            break;
        }
    }

    printf("DH key exchanges of each is verified\n");

    for(int j=0; j<96;j++)
    {
        if(j<32) dh_final_alice[j] = dh1_alice[j]; 
        if(j>=32 && j< 64)  dh_final_alice[j] = dh2_alice[j%32]; 
        if(j>=64)  dh_final_alice[j] = dh3_alice[j%32]; 
    }

    for(int j=0; j<96;j++)
    {
        if(j<32) dh_final_bob[j] = dh1_bob[j]; 
        if(j>=32 && j< 64)  dh_final_bob[j] = dh2_bob[j%32]; 
        if(j>=64)  dh_final_bob[j] = dh3_bob[j%32]; 
    }

    printf("Verifying same outputs of dh for bob and alice and making sure everything has been copied/concatenated\n");
    for (int i = 0; i < 96; i++) {
        if(i<32)
        {
            printf("%d\t%d\t%d\t%d\n",dh1_alice[i], dh1_bob[i], dh_final_alice[i],dh_final_bob[i]);
            continue;
        }
        if(i>=32 && i<64)
        {
            if(i==32) printf("\nAt Dh2\n");
            printf("%d\t%d\t%d\t%d\n",dh2_alice[i%32], dh2_bob[i%32],dh_final_alice[i],dh_final_bob[i]);
            continue;
        }
        else{
            if(i==64) printf("\nAt Dh3\n");
            printf("%d\t%d\t%d\t%d\n",dh3_alice[i%32], dh3_bob[i%32],dh_final_alice[i],dh_final_bob[i]);
            continue;
        }
    }
    for (int i = 0; i < 96; ++i) {
        // printf("%d\t%d\n",dh_final_alice[i], dh_final_bob[i]);
        if (dh_final_alice[i] != dh_final_bob[i]) {
            printf("dh final key exchange was incorrect\n");
            break;
        }
    }
    printf("DH outputs are verified\n");
    // printf("\nDH1: %d\nDH2: %d\nDH3: %d\n", strcmp(dh1_alice, dh1_bob), strcmp(dh2_alice, dh2_bob), strcmp(dh3_alice, dh3_bob));

    get_shared_key(dh_final_alice, SHA512, NULL, NULL, hex_hkdf_output_alice, 128);
    get_shared_key(dh_final_bob, SHA512, NULL, NULL, hex_hkdf_output_bob, 128);

    for(int i=0; i<128;i++)
    {
        printf("%d\t%d\n",hex_hkdf_output_alice[i],hex_hkdf_output_bob[i]);
        if(hex_hkdf_output_alice[i]!=hex_hkdf_output_bob[i])
        {
            printf("hex_hkdf_outputs are invalid\n");
        }
    }
    printf("hex_hkdf_outputs are valid\n");

    return 0;
}


void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt, const unsigned char *info,
     unsigned char* output_key, int okm_len){
    int salt_len; //The length of the salt value (a non-secret random value) (ignored if SALT==NULL)
    int info_len; // The length of optional context and application (ignored if info==NULL)
    int ikm_len; //The length of the input keying material
    uint8_t okm_integer[okm_len]; //output keying material - okm
    ikm_len = 96;
    // printf("%d\n", ikm_len);
    if(salt == NULL) salt_len = 0;
    if(info == NULL) info_len = 0;



    if(hkdf(whichSha,salt,salt_len,dh_final,ikm_len,info,info_len,okm_integer,okm_len) == 0)
    {
        printf("HKDF is valid\n");
    } else {
        fprintf(stderr, "\nHKDF is invalid\n");
    }

    for(int i=0; i<okm_len;i++)
    {
        output_key[i] = okm_integer[i];
        // printf("%d\n", output_key[i]);
    }

}
