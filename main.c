#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "blockchain.h"

void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int main() {
    printf("====================================================\n");
    printf("   TOKENIZED BLOCKCHAIN ATTENDANCE INITIALIZATION\n");
    printf("====================================================\n");

    // 1. Load Registry & Initialize Ledgers
    if (!load_students("students.txt")) {
        printf("\n[FATAL] System halted. Please ensure students.txt exists.\n");
        return 1; 
    }
    init_accounts();

    // 2. Generate Cryptographic Keys
    generate_keypair();

    // 3. Load or Initialize Blockchain
    if (load_chain()) {
        printf("SUCCESS: Blockchain successfully restored from disk.\n");
    } else {
        printf("NOTICE: No previous chain found. Initializing Genesis Block...\n");
        init_blockchain();
        sign_block(blockchain_head);
    }

    // --- SESSION CONFIGURATION ---
    printf("\n=== CONFIGURE SESSION ===\n");
    printf("Select Transaction Ledger Model:\n");
    printf("1. UTXO Model\n");
    printf("2. Account-Based Model\n");
    printf("Choice (1 or 2): ");
    if (scanf("%d", &active_ledger_model) != 1 || (active_ledger_model != 1 && active_ledger_model != 2)) {
        active_ledger_model = 1; // Default fallback
    }
    clear_input_buffer();
    printf("-> System set to use %s Model.\n", (active_ledger_model == 1) ? "UTXO" : "Account-Based");

    printf("\nSet Mining Difficulty (1 to 4): ");
    if (scanf("%d", &mining_difficulty) != 1 || mining_difficulty < 1 || mining_difficulty > 4) {
        mining_difficulty = 2; // Default fallback
    }
    clear_input_buffer();
    printf("-> PoW target set to %d leading zeros.\n", mining_difficulty);
    int choice;
    char input_id[20], input_course[10], input_status[10];

    

    return 0;
}
