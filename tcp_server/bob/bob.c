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

#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "crypto_aead.h"
#include "espHelper.h"
#include "mic.h"
#include "../X3DH/ed25519/src/ed25519.h"
#include "../X3DH/sha/rfc6234/sha.h"

#define UART_ID uart1
#define BAUD_RATE 115200
#define UART_TX_PIN 4
#define UART_RX_PIN 5

// function declerations
void createClient();
void sendMic(absolute_time_t *current, char *sampleArr,
             PIO *pio, uint *sm,
             const size_t SAMPLE_ARR_SIZE,
             char *cipCommand,
             const size_t BUFFER_SIZE,
             unsigned char hex_hkdf_output);
int FetchPreKeyBundle(unsigned char *bob_id_public_key, unsigned char *bob_spk_public_key, unsigned char *bob_spk_signature, int message_type){};
void get_dh_output(unsigned char *bob_id_public_key, unsigned char *ephemeral_private_key, unsigned char *id_private_key,
                   unsigned char *bob_spk_public_key, unsigned char *dh_final);
void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt_len, const unsigned char *info,
                    unsigned char *output_key, int okm_len);
void encrypt(const unsigned char *m, unsigned long long mlen, const unsigned char *k, char* c, uint64_t* c_length);

int main(void)
{
    stdio_init_all();
    /*----------------------------------CONNECT TO SERVER----------------------------------*/
    printf("initializing esp\n");
    createClient();
    printf("init esp complete\n");

    /*----------------------------------LISTEN TO SERVER----------------------------------*/
    // loop until message received
    // while (FetchPreKeyBundle(bob_id_public_key, bob_spk_public_key, bob_spk_signature, 2) == 1)
    // {
    //     /**
    //      * Waiting for server to send prekey bundle
    //      */
    //     continue;
    // }

    /*------------------------------------FINISH X3DH-------------------------------------*/
    //variables
    unsigned char bob_id_public_key[32];  // bob's identity key
    unsigned char bob_spk_public_key[32]; // bob's signed prekey
    unsigned char bob_spk_signature[64];  // bob's signed prekey signature
    unsigned char id_public_key[32];      // alice identity public key
    unsigned char id_private_key[64];     // alice identity private key
    unsigned char seed[32];               // Seed to generate new keys
    unsigned char scalar[32];             // Scalar to add to modify key
    unsigned char ephemeral_public_key[32];
    unsigned char ephemeral_private_key[64];
    const unsigned char message[120]; // Message of the audio file to send - message size is still varying
    const int message_len = strlen((char *)message);
    unsigned char dh_final[96];         // To store the concatenation of the dh outputs
    unsigned char hex_hkdf_output[128]; // The 128-bit key for encryptig the audio

    // Creating Long-term keypair for Alice
    ed25519_create_seed(seed);
    ed25519_create_keypair(id_public_key, id_private_key, seed);

    if (ed25519_verify(bob_spk_signature, bob_id_public_key))
    {
        printf("valid signature\n");
    }
    else
    {
        printf("invalid signature\n");
        // Abort();
    }

    // After verification, generate Ephemeral Key pair
    ed25519_create_seed(seed);
    ed25519_create_keypair(ephemeral_private_key, ephemeral_public_key, seed);

    get_dh_output(bob_id_public_key, ephemeral_private_key, id_private_key, bob_spk_public_key, dh_final);
    get_shared_key(dh_final, SHA512, NULL, NULL, hex_hkdf_output, 128);
    /*-------------------------------WAIT FOR START BUTTON--------------------------------*/

    /*------------------------------------GET MIC AUDIO-----------------------------------*/
    // variables
    // const size_t SIZE_OF_END = 3;
    const size_t SIZE_OF_END = 1;
    // const size_t BUFFER_SIZE = ((SAMPLE_FREQUENCY * BYTES_PER_SAMPLE) / 2);
    const size_t BUFFER_SIZE = 24;
    // below stores 8, 32-bit values
    // const size_t BUFFER_SIZE = ((BYTES_PER_SAMPLE) * 8);

    // const size_t SAMPLE_ARR_SIZE = BUFFER_SIZE + SIZE_OF_END;
    const size_t SAMPLE_ARR_SIZE = BUFFER_SIZE + SIZE_OF_END;
    // there are 8 samples, each 4 bytes and each char is a byte, so there should be (8 * 4) / (1char/1byte) chars
    // for (size_t i = 0; i < 10; i++)
    // {
    //     printf("%d\n", i);
    //     sleep_ms(1000);
    // }
    
    unsigned char sampleArr[SAMPLE_ARR_SIZE];
    PIO pio;
    uint sm;
    initMic(&pio, &sm);
    // int32_t sample;
    char cipCommand[80];
    absolute_time_t current = get_absolute_time();
    char testSample[] = {0xFF, 0xFF, 0x00, 0x00};
    char espResponse[256];
    /*---------------LOOP "ENCRYPT AUDIO" & "SEND ENCRYPTED AUDIO" FOREVER----------------*/

    /*-----------------------------------ENCRYPT AUDIO------------------------------------*/

    /*--------------------------------SEND ENCRYPTED AUDIO--------------------------------*/
    while (true)
    {
        sendMic(&current, sampleArr, &pio, &sm, SAMPLE_ARR_SIZE, cipCommand, BUFFER_SIZE, hex_hkdf_output);
        // to get this working, first send the at command (cipsend), then wait for an OK, then send the data, then wait for a "SEND OK" then repeat
        // sendCip(4, cipCommand);
        // printf("cipCommand is: %s", cipCommand);
        // // strcat(cipCommand, "\r\n");
        // uart_puts(UART_ID, cipCommand);
        // while (!waitUntilReady(espResponse, 256, UART_ID)) {
        //     uart_puts(UART_ID, cipCommand);
        //     printf("%s", espResponse);
        // }
        // // uart_puts(UART_ID, "\r\n");
        // printf("sending test\n");
        // uart_puts(UART_ID, "test\r\n");
        // strcpy(espResponse, "");
        // printf("waiting for SEND OK\n");
        // while (!searchStringOnce("SEND OK", espResponse)) {
        //     char input;
        //     input = uart_getc(UART_ID);
        //     printf("%s", espResponse);
        //     strncat(espResponse, &input, 1);
        // }
        // printf("SEND OK found\n");
        // strcpy(espResponse, "");
    }
    return 0;
}

void createClient()
{
    // initialize esp client
    initEsp();
    char currentString[256] = "";
    printf("setting station mode\n");
    uart_puts(UART_ID, "AT+CWMODE=1\r\n");
    while (!waitUntilReady(currentString, 256, UART_ID))
    {
        uart_puts(UART_ID, "AT+CWMODE=1\r\n");
        printf(currentString);
    }
    // printf("disabling server\n");
    // uart_puts(UART_ID, "AT+CIPSERVER=0\r\n");
    // while (!waitUntilReady(currentString, 256, UART_ID))
    // {
    //     uart_puts(UART_ID, "AT+CIPSERVER=0\r\n");
    //     printf(currentString);
    // }
    printf("enabling single connection mode\n");
    uart_puts(UART_ID, "AT+CIPMUX=0\r\n");
    while (!waitUntilReady(currentString, 256, UART_ID))
    {
        uart_puts(UART_ID, "AT+CIPMUX=0\r\n");
        printf(currentString);
    }
    printf("disconnecting from AP\n");
    uart_puts(UART_ID, "AT+CWQAP\r\n");
    while (!waitUntilReady(currentString, 256, UART_ID))
    {
        uart_puts(UART_ID, "AT+CWQAP\r\n");
        printf(currentString);
    }
    printf("\nconnecting to wifi\n");
    uart_puts(UART_ID, "AT+CWJAP=\"expressif\",\"1234567890\"\r\n");
    while (!waitUntilReady(currentString, 256, UART_ID))
    {
        uart_puts(UART_ID, "AT+CWJAP=\"expressif\",\"1234567890\"\r\n");
        printf(currentString);
    }
    for (size_t i = 0; i < 10; i++)
    {
        printf("%d\n", i);
        sleep_ms(1000);
    }
    printf("requesting ip info\n");
    uart_puts(UART_ID, "AT+CIPSTA?\r\n");
    while (!waitUntilReady(currentString, 256, UART_ID))
    {
        uart_puts(UART_ID, "AT+CIPSTA?\r\n");
        printf(currentString);
    }
    printf(currentString);
    for (size_t i = 0; i < 10; i++)
    {
        printf("%d\n", i);
        sleep_ms(1000);
    }
    // change the ip based on the previous command output
    printf("connecting to server\n");
    uart_puts(UART_ID, "AT+CIPSTART=\"TCP\",\"192.168.4.1\",2399\r\n");
    while (!waitUntilReady(currentString, 256, UART_ID))
    {
        uart_puts(UART_ID, "AT+CIPSTART=\"TCP\",\"192.168.4.1\",2399\r\n");
        printf(currentString);
    }
}

/**
 * @brief get samples, store into sampleArr, then send it to alice
 * @note variables initialized outside
 *
 * @param current time variable
 * @param sampleArr array of samples to send
 * @param pio pio instance of mic program
 * @param sm state machine of the mic program
 * @param SAMPLE_ARR_SIZE size of the sample array
 * @param cipCommand at command to send
 * @param BUFFER_SIZE size of the whole array being sent
 */
void sendMic(absolute_time_t *current, char *sampleArr,
             PIO *pio, uint *sm,
             const size_t SAMPLE_ARR_SIZE,
             char *cipCommand,
             const size_t BUFFER_SIZE,
             unsigned char hex_hkdf_output)
{
    int32_t sample = 0;
    char espResponse[256];
    *current = get_absolute_time();
    // fill in 32 bits at a time; 4 chars at once
    printf("beginning to get sample\n");
    strcpy(sampleArr, "");
    for (uint64_t i = 0; i < (SAMPLE_ARR_SIZE) - ((SAMPLE_ARR_SIZE) % 4); i += 4)
    {
        sample = getSingleSampleBlocking(pio, sm);
        sampleArr[i] = (sample >> 24) & 0x000000FF;
        sampleArr[i + 1] = (sample >> 16) & 0x000000FF;
        sampleArr[i + 2] = (sample >> 8) & 0x000000FF;
        sampleArr[i + 3] = (sample)&0x000000FF;
        printf("i is: %llu\n", i);
        printf("sampleArr is: ");
        printf("sample is: %08x\n", sample);
        for (size_t j = 0; j < 4; j++)
        {
            printf("%02X", sampleArr[i + j]);
        }
        printf("\n");
        if (!printTimer(current, 1000 * 10))
        {
            // printf("sampleArr is: ");
            // for (size_t j = 0; j < 4; j++)
            // {
            //     printf("%02X", sampleArr[i + j]);
            // }
            // printf("\n");
            *current = get_absolute_time();
        }
    }
    unsigned long long c_length = SAMPLE_ARR_SIZE;                                          // ciphertext length
    unsigned char c[c_length];                                                              // ciphertext
    const unsigned char k[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}; // 128-bit key
    encrypt(sampleArr, BUFFER_SIZE, hex_hkdf_output, c, &c_length);
    
    // sampleArr[33] = '\0';
    sendCip(c_length, cipCommand);
    printf("Command is: %s", cipCommand);
    // printf("length of sampleArr is: %d", strlen(sampleArr));
    uart_puts(UART_ID, cipCommand);
    // TODO repeat the cip command if there's an error

    printf("waiting for OK\n");
    while (!waitUntilReady(espResponse, 256, UART_ID))
    {
        uart_puts(UART_ID, cipCommand);
        // printf("%s", espResponse);
    }
    printf("found OK, ready for data\n");
    for (size_t i = 0; i < c_length; i++)
    {
        uart_putc(UART_ID, c[i]);
    }
    // uart_puts(UART_ID, sampleArr);
    strcpy(espResponse, "");
    printf("sent data waiting for SEND OK\n");
    while (!searchStringOnce("SEND OK", espResponse))
    {
        char input;
        input = uart_getc(UART_ID);
        // printf("%s", espResponse);
        strncat(espResponse, &input, 1);
    }
    strcpy(espResponse, "");
    printf("SUCCESS, stuff sent is: ");
    // read a char at a time
    for (uint64_t i = 0; i < c_length; i++)
    {
        // printf("i is: %llu|", i);
        printf("%02X|", c[i]);
    }
    printf("\n");
}

void encrypt(const unsigned char *m, unsigned long long mlen, const unsigned char *k, char* c, uint64_t* c_length)
{
    // unsigned long long c_length = 80;                                                                      // ciphertext length
    // unsigned char c[c_length];                                                                             // ciphertext
    unsigned long long *clen = c_length;                                                                  // ciphertext length pointer
    const unsigned char ad[] = {0x00};                                                                     // associated data
    unsigned long long adlen = sizeof(ad);                                                                 // associated data length
    const unsigned char *nsec;                                                                             // secret message number
    const unsigned char npub[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B}; // public message number

    crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);

    printf("Ciphertext = ");
    for (int i = 0; i < *c_length; i++)
    {
        printf("%02X|", c[i]);
    }
}

void get_dh_output(unsigned char *bob_id_public_key, unsigned char *alice_ephemeral_private_key, unsigned char *alice_id_private_key,
                   unsigned char *bob_spk_public_key, unsigned char *dh_final)
{
    // DH outputs
    unsigned char dh1[32], dh2[32], dh3[32]; // DH exchanges - no opk so only 3 outputs

    ed25519_key_exchange(dh1, bob_spk_public_key, alice_id_private_key);

    // DH2 = DH(EKA, IKB)
    ed25519_key_exchange(dh2, bob_id_public_key, alice_ephemeral_private_key);

    // DH3 = DH(EKA, SPKB)
    ed25519_key_exchange(dh3, bob_spk_public_key, alice_ephemeral_private_key);

    // Concatenating dh outputs - because strcat, strncat and memcpy doesn't seem to work.
    for (int j = 0; j < 96; j++)
    {
        if (j < 32)
            dh_final[j] = dh1[j];
        if (j >= 32 && j < 64)
            dh_final[j] = dh2[j % 32];
        if (j >= 64)
            dh_final[j] = dh3[j % 32];
    }
}

void get_shared_key(unsigned char *dh_final, SHAversion whichSha, const unsigned char *salt, const unsigned char *info,
                    unsigned char *output_key, int okm_len)
{
    int salt_len; // The length of the salt value (a non-secret random value) (ignored if SALT==NULL)
    int info_len; // The length of optional context and application (ignored if info==NULL)
    int ikm_len;  // The length of the input keying material
    uint8_t okm_integer[okm_len];
    ikm_len = 96;

    if (salt == NULL)
        salt_len = 0;
    if (info == NULL)
        info_len = 0;

    if (hkdf(whichSha, salt, salt_len, dh_final, ikm_len, info, info_len, okm_integer, okm_len) == 0)
    {
        printf("HKDF is valid\n");
    }
    else
    {
        fprintf(stderr, "HKDF is invalid\n");
    }

    for (int i = 0; i < okm_len; i++)
    {
        output_key[i] = okm_integer[i];
        printf("%d\n", output_key[i]);
    }
}