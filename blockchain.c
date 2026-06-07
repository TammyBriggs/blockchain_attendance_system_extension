#include "blockchain.h"

// Instantiate global variables
Student registry[MAX_STUDENTS];
int student_count = 0;
Block* blockchain_head = NULL;
PendingNode* pending_pool_head = NULL; // Mempool head

// --- SEGMENT 1: STUDENT REGISTRY ---

int load_students(const char* filename) {
    FILE *file = fopen(filename, "r");
    
    // Error handling: Missing file
    if (file == NULL) {
        printf("ERROR: Could not open file '%s'. File may be missing.\n", filename);
        return 0; 
    }

    // Error handling: Empty file
    fseek(file, 0, SEEK_END);
    if (ftell(file) == 0) {   
        printf("ERROR: '%s' is empty.\n", filename);
        fclose(file);
        return 0;
    }
    rewind(file); 

    char line[150];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0; // Strip newline

        char *id = strtok(line, ",");
        char *name = strtok(NULL, ",");
        char *course = strtok(NULL, ",");

        if (id && name && course) {
            strncpy(registry[student_count].student_id, id, sizeof(registry[student_count].student_id) - 1);
            strncpy(registry[student_count].full_name, name, sizeof(registry[student_count].full_name) - 1);
            strncpy(registry[student_count].course_code, course, sizeof(registry[student_count].course_code) - 1);
            student_count++;
        }
    }

    fclose(file);
    printf("SUCCESS: Loaded %d students from the registry.\n", student_count);
    return 1;
}

// --- SEGMENT 2: BLOCKCHAIN DATA STRUCTURE ---

void calculate_hash(Block* block, char* output_hash) {
    char data[1024];
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Concatenate block data for hashing
    snprintf(data, sizeof(data), "%d%ld%s%s%s%s%s", 
            block->index, 
            block->timestamp, 
            block->student_id, 
            block->full_name, 
            block->course_code, 
            block->status, 
            block->previous_hash);

    // Perform SHA-256 hash using OpenSSL
    SHA256((unsigned char*)data, strlen(data), hash);

    // Convert raw bytes to hexadecimal string
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hash + (i * 2), "%02x", hash[i]);
    }
    output_hash[64] = '\0';
}

void init_blockchain() {
    // Allocate memory for Genesis Block
    Block* genesis = (Block*)malloc(sizeof(Block));
    if (!genesis) {
        printf("ERROR: Memory allocation failed for Genesis Block.\n");
        exit(1);
    }

    // Initialize Genesis Block data
    genesis->index = 0;
    genesis->timestamp = time(NULL);
    strcpy(genesis->student_id, "SYSTEM");
    strcpy(genesis->full_name, "Genesis Block");
    strcpy(genesis->course_code, "NONE");
    strcpy(genesis->status, "SYSTEM");
    
    // previous_hash set to 64 zeros (Rubric Requirement)
    memset(genesis->previous_hash, '0', 64);
    genesis->previous_hash[64] = '\0';
    
    // Zero out signature for now
    memset(genesis->signature, 0, 72);

    // Calculate and set hash
    calculate_hash(genesis, genesis->hash);
    
    // Set as head of the linked list
    genesis->next = NULL;
    blockchain_head = genesis;

    printf("SUCCESS: Genesis Block initialized.\n");
    printf("         Hash: %.15s...\n", genesis->hash);
}

// --- SEGMENT 3: CRYPTOGRAPHY & DIGITAL SIGNATURES ---

EVP_PKEY* admin_keypair = NULL;

void generate_keypair() {
    // 1. Try to load an existing key from the hard drive
    FILE *keyfile = fopen("admin_key.pem", "rb");
    if (keyfile != NULL) {
        admin_keypair = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
        fclose(keyfile);
        
        if (admin_keypair != NULL) {
            printf("SUCCESS: Loaded existing Admin Cryptographic Keypair from disk.\n");
            return; // Exit the function, we have our key!
        }
    }

    // 2. If no key file exists, generate a brand new one
    printf("NOTICE: No existing key found. Generating new Admin Cryptographic Keypair...\n");
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &admin_keypair);
    EVP_PKEY_CTX_free(pctx);
    
    // 3. Save this newly generated key to a secure .pem file for future sessions
    keyfile = fopen("admin_key.pem", "wb");
    if (keyfile != NULL) {
        PEM_write_PrivateKey(keyfile, admin_keypair, NULL, NULL, 0, NULL, NULL);
        fclose(keyfile);
        printf("SUCCESS: New Admin Keypair saved to 'admin_key.pem'.\n");
    } else {
        printf("ERROR: Failed to save keypair to disk.\n");
    }
}

void sign_block(Block* block) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    
    // Initialize signing operations using SHA-256 and the Admin's private key
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, admin_keypair);
    
    // We sign the computed hash of the block to ensure data integrity
    EVP_DigestSignUpdate(mdctx, block->hash, strlen(block->hash));
    
    size_t sig_len = sizeof(block->signature);
    memset(block->signature, 0, sig_len); // Clear out any old garbage memory
    
    // Finalize the signature and store it directly in the block struct
    EVP_DigestSignFinal(mdctx, block->signature, &sig_len);
    EVP_MD_CTX_free(mdctx);
}

int verify_signature(Block* block) {
    // Trick: Find the actual length of the DER encoded signature.
    // DER sequences start with 0x30, followed by the length of the remaining bytes.
    if (block->signature[0] != 0x30) {
        return 0; // Invalid format, likely an empty/tampered signature
    }
    size_t actual_sig_len = block->signature[1] + 2;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    
    // Initialize verification using the Admin's public key
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, admin_keypair);
    EVP_DigestVerifyUpdate(mdctx, block->hash, strlen(block->hash));
    
    // Returns 1 if valid, 0 if invalid
    int result = EVP_DigestVerifyFinal(mdctx, block->signature, actual_sig_len);
    EVP_MD_CTX_free(mdctx);
    
    return (result == 1); 
}

// --- SEGMENT 4: MARKING ATTENDANCE ---

// MEMPOOL / PENDING POOL LOGIC
void add_to_pending_pool(const char* student_id, const char* full_name, const char* course_code, const char* status) {
    // Edge Case Handling: ABSENT students generate no transaction
    if (strcmp(status, "ABSENT") == 0) {
        printf("Record for %s ignored. Status: ABSENT (0 tokens).\n", full_name);
        return; 
    }

    // Allocate memory for the new unconfirmed transaction
    PendingNode* new_node = (PendingNode*)malloc(sizeof(PendingNode));
    if (new_node == NULL) {
        printf("Critical Error: memory allocation failed for pending pool node.\n");
        return;
    }

    // Safely copy strings
    strncpy(new_node->student_id, student_id, sizeof(new_node->student_id) - 1);
    strncpy(new_node->full_name, full_name, sizeof(new_node->full_name) - 1);
    strncpy(new_node->course_code, course_code, sizeof(new_node->course_code) - 1);
    strncpy(new_node->status, status, sizeof(new_node->status) - 1);
    
    // Ensure null-termination
    new_node->student_id[19] = '\0';
    new_node->full_name[49] = '\0';
    new_node->course_code[9] = '\0';
    new_node->status[9] = '\0';

    // Assign token reward based on status
    new_node->token_reward = (strcmp(status, "PRESENT") == 0) ? 10 : 5;
    
    // Insert at the head of the pending pool linked list
    new_node->next = pending_pool_head;
    pending_pool_head = new_node;

    printf("Added to Pending Pool: %s (%s) | Reward: %d tokens\n", 
           new_node->full_name, new_node->student_id, new_node->token_reward);
}

// --- PUSH TO MEMPOOL ---
int mark_attendance(const char* student_id, const char* course_code, const char* status) {
    // 1. Validate the Student ID against our loaded registry
    int student_found = 0;
    Student* matched_student = NULL;
    
    for (int i = 0; i < student_count; i++) {
        if (strcmp(registry[i].student_id, student_id) == 0) {
            student_found = 1;
            matched_student = &registry[i];
            break;
        }
    }

    // Reject and print error if ID not found
    if (!student_found) {
        printf("ERROR: Student ID '%s' not found in registry. Attendance aborted.\n", student_id);
        return 0;
    }

    // 2. Route the valid record to the pending pool instead of directly mining
    add_to_pending_pool(matched_student->student_id, matched_student->full_name, course_code, status);

    return 1;
}

// --- SEGMENT 5: VALIDATION & TAMPER DETECTION ---

int validate_chain() {
    Block* current = blockchain_head;
    Block* previous = NULL;
    char recalculated_hash[65];

    printf("\nAuditing Blockchain Integrity...\n");

    while (current != NULL) {
        // 1. Verify Hash Integrity
        calculate_hash(current, recalculated_hash);
        if (strcmp(current->hash, recalculated_hash) != 0) {
            printf("[!] VALIDATION FAILED: Hash mismatch detected at Block %d!\n", current->index);
            printf("    Expected: %s\n    Actual:   %s\n", current->hash, recalculated_hash);
            return 0; // Invalid
        }

        // 2. Verify Cryptographic Signature
        if (!verify_signature(current)) {
            printf("[!] VALIDATION FAILED: Invalid ECDSA signature at Block %d!\n", current->index);
            return 0; // Invalid
        }

        // 3. Verify Chain Linkage (Previous Hash)
        if (previous != NULL) {
            if (strcmp(current->previous_hash, previous->hash) != 0) {
                printf("[!] VALIDATION FAILED: Broken link between Block %d and Block %d!\n", previous->index, current->index);
                return 0; // Invalid
            }
        } else {
            // It is the Genesis Block. Rubric: Verify previous_hash is 64 zeros.
            char zeros[65];
            memset(zeros, '0', 64);
            zeros[64] = '\0';
            if (strcmp(current->previous_hash, zeros) != 0) {
                printf("[!] VALIDATION FAILED: Genesis block previous_hash has been altered!\n");
                return 0; // Invalid
            }
        }

        previous = current;
        current = current->next;
    }
    
    printf("SUCCESS: Blockchain is perfectly valid and cryptographically secure.\n");
    return 1; // Valid
}

void tamper_block(int target_index, const char* new_status) {
    Block* current = blockchain_head;
    
    while (current != NULL) {
        if (current->index == target_index) {
            printf("\n--- MALICIOUS ACTOR SIMULATION ---\n");
            printf("Hacking Block %d...\n", target_index);
            printf("Old Status: %s\n", current->status);
            
            // Maliciously alter the data directly in memory
            strncpy(current->status, new_status, sizeof(current->status) - 1);
            current->status[sizeof(current->status) - 1] = '\0';
            
            printf("New Status: %s\n", current->status);
            printf("Notice: Hacker did not recalculate hashes or signatures.\n");
            return;
        }
        current = current->next;
    }
    printf("Tamper failed: Block %d not found.\n", target_index);
}

// --- SEGMENT 6: DATA PERSISTENCE & VIEWING ---

void save_chain() {
    FILE *file = fopen("blockchain.dat", "wb"); // 'wb' = write binary
    if (file == NULL) {
        printf("ERROR: Could not open file to save blockchain.\n");
        return;
    }

    Block* current = blockchain_head;
    int blocks_saved = 0;
    
    // Iterate through the chain and write each block to disk
    while (current != NULL) {
        fwrite(current, sizeof(Block), 1, file);
        current = current->next;
        blocks_saved++;
    }

    fclose(file);
    printf("SUCCESS: Saved %d blocks to disk ('blockchain.dat').\n", blocks_saved);
}

int load_chain() {
    FILE *file = fopen("blockchain.dat", "rb"); // 'rb' = read binary
    if (file == NULL) {
        // Normal behavior on very first run when no file exists yet
        return 0; 
    }

    Block temp_block;
    Block* current = NULL;
    int blocks_loaded = 0;

    // Read one block's worth of bytes at a time
    while (fread(&temp_block, sizeof(Block), 1, file)) {
        // Allocate fresh memory for the block in this new session
        Block* new_block = (Block*)malloc(sizeof(Block));
        *new_block = temp_block; 
        
        // CRITICAL: We must rebuild the pointers! The old ones are dead memory.
        new_block->next = NULL;

        if (blockchain_head == NULL) {
            blockchain_head = new_block; // First block read becomes the head
        } else {
            current->next = new_block;   // Link to the previous block
        }
        current = new_block;
        blocks_loaded++;
    }

    fclose(file);
    printf("SUCCESS: Loaded %d blocks from disk.\n", blocks_loaded);
    return 1; // Success
}

void view_records() {
    printf("\n================================ ATTENDANCE LEDGER ================================\n");
    Block* current = blockchain_head;
    
    if (current == NULL) {
        printf("Ledger is empty.\n");
        return;
    }

    while (current != NULL) {
        char time_str[26];
        struct tm* tm_info = localtime(&current->timestamp);
        strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);

        // --- THE FIX IS HERE ---
        // 1. Recalculate the hash from the current data
        char recalculated_hash[65];
        calculate_hash(current, recalculated_hash);
        
        // 2. Check if the data has been altered
        int is_data_unaltered = (strcmp(current->hash, recalculated_hash) == 0);
        
        // 3. Check the cryptographic signature
        int is_sig_valid = verify_signature(current);

        // It is only truly valid if BOTH the data is untouched AND the signature is real
        int overall_valid = (is_data_unaltered && is_sig_valid);

        printf("Block [%d] | Time: %s\n", current->index, time_str);
        
        if (current->index == 0) {
            printf("  -> [SYSTEM GENESIS BLOCK]\n");
        } else {
            printf("  -> Student: %-15s | ID: %-8s | Course: %-8s\n", 
                   current->full_name, current->student_id, current->course_code);
            printf("  -> Status:  %-15s\n", current->status);
        }
        
        // Output the strict validation result
        printf("  -> Record Status: [%s]\n", overall_valid ? "VALID & AUTHENTIC" : "INVALID/TAMPERED");
        printf("  -> Hash: %.20s...\n", current->hash);
        printf("-----------------------------------------------------------------------------------\n");

        current = current->next;
    }
}
