# Tokenized Blockchain Attendance System

A C-based decentralized ledger simulation that extends a basic blockchain structure by introducing a tokenized economy. This system tokenizes student attendance, utilizing a mempool for unconfirmed transactions, and implements both **UTXO** and **Account-Based** ledger models secured by **Proof-of-Work (PoW)** mining.

## Additional Dependencies
This project requires the **OpenSSL** library for cryptographic hashing (`SHA-256`) and digital signatures (`secp256r1` ECDSA). There are no other external dependencies.

**For Linux (Ubuntu/Debian/WSL):**
```bash
sudo apt-get update
sudo apt-get install libssl-dev
```

**For macOS (via Homebrew):**
```bash
brew install openssl
```

## Updated Compilation Instructions
To build the application, navigate to the project directory in your terminal and compile the source files. You must link the OpenSSL crypto library using the `-lcrypto` flag for the build to succeed.
```bash
gcc main.c blockchain.c -o attendance_system -lcrypto
```

## How to Switch Between Transaction Models
Transaction models are selected at the start of a new session. When you execute the program (`./attendance_system`), the system will prompt you with a "Configure Session" menu before the main CLI loop begins.

* Enter `1` to boot the system using the UTXO Model.
* Enter `2` to boot the system using the Account-Based Model.
* Note: The chosen model applies globally to all token transactions for the duration of that session.

## How to Set Mining Difficulty Level
Immediately after selecting your transaction model during the startup configuration, the system will prompt you to set the Mining Difficulty.

* You can enter a value between `1` and `4`.
* This value dictates the number of leading zeros required for a valid Proof-of-Work hash (e.g., a difficulty of 2 requires a hash starting with `00...`).

## How to Test Mining Simulations
To properly test the mining simulators, you must first generate unconfirmed transactions.

1. Populate the Mempool: Select Option 1 (Mark Attendance) from the main menu and mark a student as `PRESENT` or `LATE`. This routes a token reward transaction to the pending pool.
2. Test Solo Mining: Select Option 3. The system will perform the Proof-of-Work algorithm, print the number of hash attempts required, deduct network fees, and permanently confirm the block to the ledger.
3. Test Pool Mining: Add another student to the pending pool using Option 1. Select Option 4. The system will distribute the hash workload among simulated miners, deduct a 2% pool fee, and print a formatted distribution table showing each miner's share and fiat reward.
4. Test Cloud Mining: Select Option 5. Enter a rental duration (e.g., `5` rounds). The system will calculate fixed rental fees against fluctuating block yields, ultimately displaying a multi-round earnings summary and indicating if the rental was profitable or unprofitable.

## Important Note on Memory & Data Integrity
If you are upgrading from the previous version of this project, you must delete your existing `blockchain.dat` file before running the program. Reading an outdated binary layout into the newly extended `Block` struct will cause memory misalignment and cryptographic validation failures.
