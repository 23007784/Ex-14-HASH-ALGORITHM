# Ex-14-HASH-ALGORITHM
## AIM
To implement Hash Function Cryptography in Python for ensuring message
integrity by generating a hash value for a given message.
## ALGORITHM
Step 1: Choose a cryptographic hash function H (e.g., SHA-256).                 
Step 2: Input the message m that needs to be hashed.          
Step 3: Compute the hash value h=H(m).                  
Step 4: The hash value h is the fixed-length output that represents the integrity of
the message.                        
Step 5: Send both the message mmm and the hash h for verification.           
Step 6: The receiver computes the hash value h′=H(m) using the received
message.                          
Step 7: If h′ matches the received hash h, the message is verified; otherwise, it is
considered altered.                       
## PROGRAM
```
#include <stdio.h>
#include <string.h>
#define MAX_LEN 256 // Maximum length of the message
#define BLOCK_SIZE 64 // Block size for the HMAC
// XOR pad function
void xor_pad(char *key, char pad, char *output, int key_len) {
for (int i = 0; i < key_len; i++) {
output[i] = key[i] ^ pad;
}
for (int i = key_len; i < BLOCK_SIZE; i++) {
output[i] = pad;
}
}
// Simple hashing function (XOR sum)
void simple_hash(const char *input, char *output) {
int len = strlen(input);
char hash_value = 0;

for (int i = 0; i < len; i++) {
hash_value ^= input[i];
}
snprintf(output, 3, "%02x", hash_value); // Store the hash as a hex string
}
// Perform HMAC-like operation
void hmac(const char *message, const char *key, char *output_mac) {
char o_key_pad[BLOCK_SIZE]; // Outer padded key
char i_key_pad[BLOCK_SIZE]; // Inner padded key
char temp[MAX_LEN + BLOCK_SIZE]; // Buffer for inner hash calculation
char inner_hash[3]; // To store the result of the inner hash
int key_len = strlen(key);
// XOR the key with inner and outer pads
xor_pad((char *)key, 0x36, i_key_pad, key_len);
xor_pad((char *)key, 0x5c, o_key_pad, key_len);
// Perform the inner hash: hash(i_key_pad || message)
strcpy(temp, i_key_pad);
strcat(temp, message);
simple_hash(temp, inner_hash); // Calculate inner hash
// Perform the outer hash: hash(o_key_pad || inner_hash)
strcpy(temp, o_key_pad);
strcat(temp, inner_hash);
simple_hash(temp, output_mac); // Calculate outer hash (final MAC)
}
// XOR-based encryption
void encrypt(const char *input, const char *key, char *output) {
int len = strlen(input);
int key_len = strlen(key);
for (int i = 0; i < len; i++) {
output[i] = input[i] ^ key[i % key_len]; // XOR encryption
}
output[len] = '\0'; // Null-terminate the encrypted string
}
// XOR-based decryption
void decrypt(const char *input, const char *key, char *output) {
encrypt(input, key, output); // XOR encryption is symmetric
}
int main() {
char message[MAX_LEN]; // Plaintext message
char key[MAX_LEN]; // Symmetric key
char mac[3]; // HMAC output
char encrypted[MAX_LEN]; // Encrypted message
char decrypted[MAX_LEN]; // Decrypted message
printf("\n *Simulation of HMAC Algorithm with Encryption and Decryption*\n\n");

// Get plaintext message from the user
printf("Enter the plaintext message: ");
fgets(message, MAX_LEN, stdin);
message[strcspn(message, "\n")] = 0; // Remove newline character
// Get symmetric key from the user
printf("Enter the symmetric key: ");
fgets(key, MAX_LEN, stdin);
key[strcspn(key, "\n")] = 0; // Remove newline character
// Perform HMAC-like operation
hmac(message, key, mac);
printf("Generated HMAC: %s\n", mac);
// Perform encryption
encrypt(message, key, encrypted);
printf("Encrypted message (raw bytes): ");
for (int i = 0; i < strlen(message); i++) {
printf("%02x ", (unsigned char)encrypted[i]);
}
printf("\n");
// Perform decryption
decrypt(encrypted, key, decrypted);
printf("Decrypted message: %s\n", decrypted);
return 0;
}
```
## OUTPUT
![crypt14](https://github.com/user-attachments/assets/a159b66f-d339-449d-8fd6-41cbb421b7d8)

## RESULT
Thus, the program for Hash Function Cryptography was executed successfully,
demonstrating its eƯectiveness in generating a secure hash value to verify
message integrity.
