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

    // --- MAIN CLI LOOP ---
    while (1) {
        printf("\n==================== MAIN MENU ====================\n");
        printf(" 1. Mark Attendance (Sends to Pending Pool)\n");
        printf(" 2. View Pending Pool Status\n");
        printf(" 3. MINE: Solo (Confirm pending blocks)\n");
        printf(" 4. MINE: Pool Simulation\n");
        printf(" 5. MINE: Cloud Rental Simulation\n");
        printf(" 6. View Confirmed Attendance Ledger\n");
        printf(" 7. View Token Balances (UTXO / Account)\n");
        printf(" 8. Validate Blockchain Integrity\n");
        printf(" 9. Manual Token Transfer (Both Models)\n");
        printf(" 10. View Transaction History (Account Model Only)\n");
        printf(" 11. Exit System\n");
        printf("===================================================\n");
        printf("Select an option (1-11): ");
        
        if (scanf("%d", &choice) != 1) {
            clear_input_buffer();
            printf("Invalid input. Please enter a number.\n");
            continue;
        }
        clear_input_buffer();

        switch (choice) {
            case 1:
                printf("\n--- Mark Attendance ---\n");
                printf("Enter Student ID: ");
                scanf("%19s", input_id);
                printf("Enter Course Code: ");
                scanf("%9s", input_course);
                printf("Enter Status (PRESENT/ABSENT/LATE): ");
                scanf("%9s", input_status);
                
                mark_attendance(input_id, input_course, input_status);
                break;

            case 2:
                view_pending_pool();
                break;

            case 3:
                mine_solo();
                break;

            case 4:
                mine_pool();
                break;

            case 5: {
                int rounds;
                printf("\nEnter number of rental rounds (1-5): ");
                scanf("%d", &rounds);
                mine_cloud(rounds);
                break;
            }

            case 6:
                view_records();
                break;

            case 7:
                if (active_ledger_model == 1) {
                    print_utxo_set();
                } else {
                    print_account_balances();
                }
                break;

            case 8:
                validate_chain();
                break;

            case 9: {
                char recipient[20];
                int amount, nonce;
                printf("\n--- Manual Token Transfer ---\n");
                printf("Sender ID: "); scanf("%19s", input_id);
                printf("Recipient ID: "); scanf("%19s", recipient);
                printf("Amount to transfer: "); scanf("%d", &amount);
                
                if (active_ledger_model == 1) {
                    // UTXO Model doesn't use nonces
                    transfer_utxo(input_id, recipient, amount);
                } else {
                    // Account Model strictly requires the nonce
                    printf("Enter sender's current Nonce + 1: "); scanf("%d", &nonce);
                    transfer_tokens(input_id, recipient, amount, nonce);
                }
                break;
            }

            case 10:
                printf("\n--- View Transaction History ---\n");
                printf("Enter Student ID: ");
                scanf("%19s", input_id);
                view_transaction_history(input_id);
                break;

            case 11:
                printf("\nSaving final state and shutting down securely...\n");
                save_chain(); // Saves the confirmed chain to disk
                printf("Goodbye!\n");
                return 0;

            default:
                printf("\nInvalid selection. Please try again.\n");
        }
    }

    return 0;
}
