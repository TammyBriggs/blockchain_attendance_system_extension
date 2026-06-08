#include "blockchain.h"

// Instantiate global variables
Student registry[MAX_STUDENTS];
int student_count = 0;
Block* blockchain_head = NULL;
PendingNode* pending_pool_head = NULL; // Mempool head
int active_ledger_model = 1;
UTXO* utxo_set_head = NULL;
Account* account_list_head = NULL;

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

    // Concatenate block data for hashing, NOW INCLUDING token_reward and nonce
    snprintf(data, sizeof(data), "%d%ld%s%s%s%s%s%d%d", 
            block->index, 
            block->timestamp, 
            block->student_id, 
            block->full_name, 
            block->course_code, 
            block->status, 
            block->previous_hash,
            block->token_reward,
            block->nonce);

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
    
    // previous_hash set to 64 zeros (Requirement)
    memset(genesis->previous_hash, '0', 64);
    genesis->previous_hash[64] = '\0';
    
    // Zero out signature for now
    memset(genesis->signature, 0, 72);

    // Initialize fields to prevent garbage memory hashes
    genesis->token_reward = 0;
    genesis->nonce = 0;

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

// --- LEDGER MODEL LOGIC ---

void process_reward_utxo(const char* student_id, int reward, const char* out_tx_id) {
    if (reward <= 0) return;

    int fee = 1; // System fee per rubric
    int net_reward = reward - fee;

    if (net_reward <= 0) return;

    UTXO* new_utxo = (UTXO*)malloc(sizeof(UTXO));
    if (!new_utxo) {
        printf("ERROR: Memory allocation failed for UTXO.\n");
        return;
    }

    strncpy(new_utxo->transaction_id, out_tx_id, sizeof(new_utxo->transaction_id) - 1);
    strncpy(new_utxo->owner_id, student_id, sizeof(new_utxo->owner_id) - 1);
    new_utxo->amount = net_reward;
    
    // Add to the head of the UTXO set
    new_utxo->next = utxo_set_head;
    utxo_set_head = new_utxo;

    printf("UTXO Generated: %s received %d tokens (Fee: %d) | TX: %.15s...\n", 
           student_id, net_reward, fee, out_tx_id);
}

void print_utxo_set() {
    printf("\n--- CURRENT UTXO SET ---\n");
    UTXO* current = utxo_set_head;
    if (current == NULL) {
        printf("UTXO Set is empty.\n");
        return;
    }
    while (current != NULL) {
        printf("Owner: %-10s | Amount: %2d | TX: %.15s...\n", 
               current->owner_id, current->amount, current->transaction_id);
        current = current->next;
    }
    printf("------------------------\n");
}

void init_accounts() {
    // Populate the account list from the loaded registry on startup
    for (int i = 0; i < student_count; i++) {
        Account* new_acc = (Account*)malloc(sizeof(Account));
        strncpy(new_acc->student_id, registry[i].student_id, sizeof(new_acc->student_id) - 1);
        new_acc->balance = 0;
        new_acc->nonce = 0;
        new_acc->history_head = NULL;
        
        new_acc->next = account_list_head;
        account_list_head = new_acc;
    }
    printf("SUCCESS: Account models initialized for %d students.\n", student_count);
}

void process_reward_account(const char* student_id, int reward, const char* out_tx_id) {
    if (reward <= 0) return;

    int fee = 1;
    int net_reward = reward - fee;

    if (net_reward <= 0) return;

    // Find the account and update the balance
    Account* current = account_list_head;
    while (current != NULL) {
        if (strcmp(current->student_id, student_id) == 0) {
            current->balance += net_reward;
            
            // Log the transaction history in memory
            TransactionRecord* tx = (TransactionRecord*)malloc(sizeof(TransactionRecord));
            strcpy(tx->sender_id, "SYSTEM");
            strcpy(tx->recipient_id, student_id);
            tx->amount = net_reward;
            tx->fee = fee;
            tx->nonce = 0; // System reward doesn't increment the user's outgoing nonce
            
            tx->next = current->history_head;
            current->history_head = tx;

            printf("Account Credited: %s received %d tokens (Fee: %d). New Balance: %d\n", 
                   student_id, net_reward, fee, current->balance);
            return;
        }
        current = current->next;
    }
    printf("ERROR: Account not found for %s\n", student_id);
}

void print_account_balances() {
    printf("\n--- ACCOUNT BALANCES ---\n");
    Account* current = account_list_head;
    if (current == NULL) {
        printf("No accounts initialized.\n");
        return;
    }
    while (current != NULL) {
        printf("Student ID: %-10s | Balance: %d\n", current->student_id, current->balance);
        current = current->next;
    }
    printf("------------------------\n");
}

int transfer_tokens(const char* sender_id, const char* recipient_id, int amount, int provided_nonce) {
    if (active_ledger_model != 2) {
        printf("ERROR: Manual transfers are only supported in the Account-Based Model.\n");
        return 0;
    }

    Account* sender = NULL;
    Account* recipient = NULL;
    Account* current = account_list_head;

    // Locate both accounts in the ledger
    while (current != NULL) {
        if (strcmp(current->student_id, sender_id) == 0) sender = current;
        if (strcmp(current->student_id, recipient_id) == 0) recipient = current;
        current = current->next;
    }

    if (!sender) { printf("ERROR: Sender %s not found.\n", sender_id); return 0; }
    if (!recipient) { printf("ERROR: Recipient %s not found.\n", recipient_id); return 0; }
    if (sender == recipient) { printf("ERROR: Cannot transfer to self.\n"); return 0; }

    int fee = 1; // Standard network fee

    // 1. NONCE VALIDATION (Replay Attack Prevention)
    // The provided nonce must be exactly one higher than the current account nonce
    int expected_nonce = sender->nonce + 1;
    if (provided_nonce < expected_nonce) {
        printf("ERROR: Transaction rejected. Nonce %d has been reused (Expected: %d).\n", provided_nonce, expected_nonce);
        return 0;
    } else if (provided_nonce > expected_nonce) {
        printf("ERROR: Transaction rejected. Nonce %d is out of sequence (Expected: %d).\n", provided_nonce, expected_nonce);
        return 0;
    }

    // 2. BALANCE VALIDATION
    if (sender->balance < (amount + fee)) {
        printf("ERROR: Transaction rejected. Insufficient balance (Balance: %d, Required: %d).\n", sender->balance, amount + fee);
        return 0;
    }

    // 3. EXECUTE TRANSFER
    sender->balance -= (amount + fee);
    recipient->balance += amount;
    sender->nonce++; // Increment nonce upon successful outgoing transaction

    // 4. LOG TRANSACTION HISTORY (For Sender)
    TransactionRecord* tx_sender = (TransactionRecord*)malloc(sizeof(TransactionRecord));
    strcpy(tx_sender->sender_id, sender_id);
    strcpy(tx_sender->recipient_id, recipient_id);
    tx_sender->amount = amount;
    tx_sender->fee = fee;
    tx_sender->nonce = sender->nonce;
    
    tx_sender->next = sender->history_head;
    sender->history_head = tx_sender;

    // 5. LOG TRANSACTION HISTORY (For Recipient)
    TransactionRecord* tx_recipient = (TransactionRecord*)malloc(sizeof(TransactionRecord));
    *tx_recipient = *tx_sender; // Copy data
    tx_recipient->next = recipient->history_head;
    recipient->history_head = tx_recipient;

    printf("SUCCESS: %d tokens transferred from %s to %s (Fee: %d). Sender new nonce: %d\n", 
           amount, sender_id, recipient_id, fee, sender->nonce);
    return 1;
}

void view_transaction_history(const char* student_id) {
    if (active_ledger_model != 2) {
        printf("ERROR: Transaction history is only available in the Account-Based Model.\n");
        return;
    }

    Account* current = account_list_head;
    while (current != NULL) {
        if (strcmp(current->student_id, student_id) == 0) {
            printf("\n--- TRANSACTION HISTORY FOR %s ---\n", student_id);
            printf("Current Balance: %d | Current Outgoing Nonce: %d\n", current->balance, current->nonce);
            
            TransactionRecord* tx = current->history_head;
            if (tx == NULL) {
                printf("No transactions found for this account.\n");
            } else {
                printf("%-10s | %-10s | %-6s | %-3s | %-5s\n", "Sender", "Recipient", "Amount", "Fee", "Nonce");
                printf("----------------------------------------------------\n");
                while (tx != NULL) {
                    printf("%-10s | %-10s | %-6d | %-3d | %-5d\n", 
                           tx->sender_id, tx->recipient_id, tx->amount, tx->fee, tx->nonce);
                    tx = tx->next;
                }
            }
            printf("----------------------------------------------------\n");
            return;
        }
        current = current->next;
    }
    printf("ERROR: Account not found for %s\n", student_id);
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

// --- PROOF OF WORK & MINING ---

int mining_difficulty = 2; // Default difficulty level (can be adjusted 1-4)

// Helper function to append a fully mined block to the chain
void append_mined_block(Block* new_block) {
    if (blockchain_head == NULL) {
        blockchain_head = new_block;
    } else {
        Block* current = blockchain_head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_block;
    }
}

void mine_solo() {
    if (pending_pool_head == NULL) {
        printf("\nPending pool is empty. No attendance blocks to mine.\n");
        return;
    }

    printf("\n--- INITIATING SOLO MINING ---\n");
    printf("Target Difficulty: %d leading zeros\n", mining_difficulty);

    char target_prefix[10];
    memset(target_prefix, '0', mining_difficulty);
    target_prefix[mining_difficulty] = '\0';

    int blocks_mined = 0;
    int total_attempts = 0;

    // Process the entire mempool
    while (pending_pool_head != NULL) {
        PendingNode* tx = pending_pool_head;
        pending_pool_head = tx->next; // Dequeue from pending pool

        // Find the current end of the chain to link the new block
        Block* tail = blockchain_head;
        while (tail->next != NULL) {
            tail = tail->next;
        }

        // Allocate and populate the new block
        Block* new_block = (Block*)malloc(sizeof(Block));
        new_block->index = tail->index + 1;
        new_block->timestamp = time(NULL);
        strncpy(new_block->student_id, tx->student_id, 19);
        strncpy(new_block->full_name, tx->full_name, 49);
        strncpy(new_block->course_code, tx->course_code, 9);
        strncpy(new_block->status, tx->status, 9);
        new_block->token_reward = tx->token_reward;
        strncpy(new_block->previous_hash, tail->hash, 64);
        new_block->previous_hash[64] = '\0';
        new_block->next = NULL;

        // --- PROOF OF WORK LOOP ---
        new_block->nonce = 0;
        int block_attempts = 0;
        do {
            new_block->nonce++;
            calculate_hash(new_block, new_block->hash);
            block_attempts++;
        } while (strncmp(new_block->hash, target_prefix, mining_difficulty) != 0);

        // Sign the successfully mined block
        sign_block(new_block);
        
        // Append to chain
        append_mined_block(new_block);

        // Process Ledger Rewards using the transaction ID (which is the block hash here)
        strncpy(new_block->transaction_id, new_block->hash, 64);
        new_block->transaction_id[64] = '\0';

        if (active_ledger_model == 1) {
            process_reward_utxo(new_block->student_id, new_block->token_reward, new_block->transaction_id);
        } else {
            process_reward_account(new_block->student_id, new_block->token_reward, new_block->transaction_id);
        }

        printf("Mined Block %d | Attempts: %d | Hash: %.15s...\n", new_block->index, block_attempts, new_block->hash);
        
        total_attempts += block_attempts;
        blocks_mined++;
        free(tx); // Free the pending node memory
    }

    printf("\n[SOLO MINING COMPLETE] Mined %d blocks using %d total hash attempts.\n", blocks_mined, total_attempts);
}

void mine_pool() {
    // For pool simulation, we will run the PoW on the first pending block, 
    // but split the credit among simulated network miners.
    if (pending_pool_head == NULL) {
        printf("\nPending pool is empty. No blocks to mine.\n");
        return;
    }

    printf("\n--- INITIATING POOL MINING ---\n");
    
    // Simulate 3 miners with random hash rates
    srand(time(NULL));
    int miner1_attempts = rand() % 5000 + 1000;
    int miner2_attempts = rand() % 5000 + 1000;
    int miner3_attempts = rand() % 5000 + 1000;
    int total_network_attempts = miner1_attempts + miner2_attempts + miner3_attempts;

    // Simulate mining the block
    mine_solo(); // We reuse the solo logic to actually do the cryptographic work on the pool

    float block_reward_fiat = 50.0; // Simulated fiat value of a mined block
    float pool_fee = block_reward_fiat * 0.02; // 2% pool fee per rubric
    float distributable_reward = block_reward_fiat - pool_fee;

    printf("\n--- POOL REWARD DISTRIBUTION TABLE ---\n");
    printf("Total Network Hashes: %d | Pool Fee Deducted: 2%%\n", total_network_attempts);
    printf("%-10s | %-10s | %-10s | %-10s\n", "Miner ID", "Attempts", "Share %", "Reward ($)");
    printf("----------------------------------------------------\n");
    
    float share1 = (float)miner1_attempts / total_network_attempts;
    printf("%-10s | %-10d | %-9.2f%% | $%-9.2f\n", "Miner 01", miner1_attempts, share1 * 100, share1 * distributable_reward);
    
    float share2 = (float)miner2_attempts / total_network_attempts;
    printf("%-10s | %-10d | %-9.2f%% | $%-9.2f\n", "Miner 02", miner2_attempts, share2 * 100, share2 * distributable_reward);
    
    float share3 = (float)miner3_attempts / total_network_attempts;
    printf("%-10s | %-10d | %-9.2f%% | $%-9.2f\n", "Miner 03", miner3_attempts, share3 * 100, share3 * distributable_reward);
}

void mine_cloud(int rental_rounds) {
    // 1. Check if there is actually anything to mine first
    if (pending_pool_head == NULL) {
        printf("\nPending pool is empty. No blocks to mine via cloud.\n");
        return;
    }

    printf("\n--- CLOUD MINING CONTRACT: %d ROUNDS ---\n", rental_rounds);
    
    if (rental_rounds < 1 || rental_rounds > 5) {
        printf("Invalid contract duration. Must be between 1 and 5 rounds.\n");
        return;
    }

    // 2. Execute the mining process using the rented cloud power!
    mine_solo();

    // 3. Calculate the economics of the rental contract
    float rental_fee_per_round = 15.0; // Fixed cost
    float total_fees = 0;
    float gross_earnings = 0;

    for (int i = 1; i <= rental_rounds; i++) {
        total_fees += rental_fee_per_round;
        
        // Simulate fluctuating block rewards per round
        float round_reward = (rand() % 20) + 5.0; 
        gross_earnings += round_reward;

        printf("Round %d | Fee Paid: $%.2f | Yield: $%.2f\n", i, rental_fee_per_round, round_reward);
    }

    float net_profit = gross_earnings - total_fees;
    
    printf("---------------------------------\n");
    printf("Gross Earnings: $%.2f\n", gross_earnings);
    printf("Total Fees:     $%.2f\n", total_fees);
    printf("Net Profit:     $%.2f\n", net_profit);

    if (net_profit < 0) {
        printf("\n[WARNING] This cloud mining contract was UNPROFITABLE. You lost $%.2f.\n", net_profit * -1);
    } else {
        printf("\n[SUCCESS] Contract yielded a positive ROI.\n");
    }
}

// --- UI HELPER FUNCTIONS ---
void view_pending_pool() {
    printf("\n--- PENDING POOL (UNCONFIRMED TRANSACTIONS) ---\n");
    if (pending_pool_head == NULL) {
        printf("The pending pool is currently empty.\n");
        return;
    }
    
    PendingNode* current = pending_pool_head;
    int count = 1;
    while (current != NULL) {
        printf("%d. Student: %-15s | ID: %-8s | Status: %-8s | Reward: %d tokens\n",
               count++, current->full_name, current->student_id, current->status, current->token_reward);
        current = current->next;
    }
    printf("-------------------------------------------------\n");
}
