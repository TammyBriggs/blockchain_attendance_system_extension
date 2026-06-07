#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define MAX_STUDENTS 100

// Student Registry Structure
typedef struct {
    char student_id[20];
    char full_name[50];
    char course_code[10];
} Student;

// Blockchain Node Structure
typedef struct Block {
    int index;
    time_t timestamp;
    char student_id[20];
    char full_name[50];
    char course_code[10];
    char status[10];
    char previous_hash[65];
    unsigned char signature[72]; // ECDSA signature (max 72 bytes)
    char hash[65];
    int token_reward;         // Coins earned: 10, 5, or 0
    char transaction_id[65];  // SHA-256 hash string for the reward transaction
    int nonce;                // Added for PoW mining

    struct Block* next;          // Pointer to link to the next block
} Block;

// Mempool structure for unconfirmed attendance events
typedef struct PendingNode {
    char student_id[20];
    char full_name[50];
    char course_code[10];
    char status[10];
    int token_reward;
    struct PendingNode* next;
} PendingNode;

// Global Variables
extern Student registry[MAX_STUDENTS];
extern int student_count;
extern Block* blockchain_head;
extern PendingNode* pending_pool_head;

// Global Cryptographic Keypair for the "Administrator"
extern EVP_PKEY* admin_keypair;

// Function Prototypes
int load_students(const char* filename);
void calculate_hash(Block* block, char* output_hash);
void init_blockchain();
void generate_keypair();
void sign_block(Block* block);
int verify_signature(Block* block);

int mark_attendance(const char* student_id, const char* course_code, const char* status);

int validate_chain();
void tamper_block(int target_index, const char* new_status);

void save_chain();
int load_chain();
void view_records();

void add_to_pending_pool(const char* student_id, const char* full_name, const char* course_code, const char* status);

#endif
