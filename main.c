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
    printf("   BLOCKCHAIN ATTENDANCE SYSTEM INITIALIZATION\n");
    printf("====================================================\n");

    // 1. Load Registry
    if (!load_students("students.txt")) {
        printf("\n[FATAL] System halted. Please ensure students.txt exists.\n");
        return 1; 
    }

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

    int choice;
    char input_id[20], input_course[10], input_status[10];

    // --- MAIN CLI LOOP ---
    while (1) {
        printf("\n================ MAIN MENU ================\n");
        printf("1. Mark Attendance\n");
        printf("2. View Attendance Ledger\n");
        printf("3. Validate Blockchain Integrity\n");
        printf("4. Simulate Malicious Tampering\n");
        printf("5. Exit System\n");
        printf("===========================================\n");
        printf("Select an option (1-5): ");
        
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
                
                if (mark_attendance(input_id, input_course, input_status) == 1) {
                    save_chain();
                }
                break;

            case 2:
                view_records();
                break;

            case 3:
                validate_chain();
                break;

            case 4: {
                int target;
                char fake_status[10];
                printf("\n--- Tamper Simulation ---\n");
                printf("Enter the Block Index to hack: ");
                scanf("%d", &target);
                printf("Enter the fake status to inject: ");
                scanf("%9s", fake_status);
                
                tamper_block(target, fake_status);
                // We do NOT save_chain() here, so the hack only lives in RAM
                break;
            }

            case 5:
                printf("\nSaving final state and shutting down securely...\n");
                save_chain();
                printf("Goodbye!\n");
                return 0;

            default:
                printf("\nInvalid selection. Please try again.\n");
        }
    }

    return 0;
}
