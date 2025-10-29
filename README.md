# AMOCA Telemedicine: Confidential Medical Data Sharing

## The Problem: Privacy-Preserving Medical Data Sharing

Medical records contain highly sensitive personal information that needs to be shared between healthcare providers, insurance companies, and patients while maintaining strict privacy controls. Traditional solutions face several challenges:

- **Privacy Risks**: Storing medical data on public blockchains exposes sensitive information
- **Trust Requirements**: Centralized solutions require trusting a single party with sensitive data
- **Compliance**: Healthcare data sharing must comply with regulations like HIPAA
- **Access Control**: Fine-grained control over who can access specific medical data is essential
- **Auditability**: All access and sharing events must be transparent and verifiable

## The Solution: AMOCA Telemedicine on Arcium MPC

AMOCA Telemedicine leverages Arcium's Multi-Party Computation (MPC) to enable decentralized, trust-minimized confidential computing on Solana. The system allows medical records to be shared while keeping the data encrypted and ensuring no single party has access to the complete information.

### Key Features

- **Dishonest Majority MPC**: Secure computation even when a majority of nodes are potentially malicious
- **Cheater Detection**: Built-in mechanisms to detect and prevent malicious behavior
- **Trustless Architecture**: No single party has access to the complete data
- **Regulatory Compliance**: Built-in privacy controls align with healthcare data regulations
- **Transparent Access**: All sharing events are recorded on-chain while preserving privacy
- **Selective Sharing**: Patients maintain control over who can access their medical data

### Encryption Flow

- Data remains encrypted at all times during storage and computation
- Only the authorized recipient can decrypt the data using their private key
- The MPC network performs computations on encrypted data without ever seeing the plaintext
- When sharing data, it's encrypted specifically for the recipient's public key
- The recipient can then decrypt the data using their private key when they receive it

## Implementation Details

### Architecture

- Regular Solana program code in the `programs` directory
- Confidential computing instructions in the `encrypted-ixs` directory using Arcium's Arcis framework
- Seamless integration with Solana's account model and Anchor framework

### Key Components

- **Encrypted Circuit**: Defined in `encrypted-ixs/src/lib.rs`, handles confidential data transfer
- **Program Instructions**:
  - `init_share_patient_data_comp_def`: Initializes the confidential computation
  - `store_patient_data`: Stores encrypted patient data on-chain
  - `share_patient_data`: Initiates the confidential data sharing process
  - `share_patient_data_with_role`: Role-gated sharing using certificate NFT
  - `share_patient_data_doctor` / `share_patient_data_nurse` / `share_patient_data_pharmacist`: Convenience wrappers for role-gated sharing

### Security Implementation

- Threshold encryption requiring multiple parties to cooperate
- Separate encryption keys for sender and receiver
- Nonce-based protection against replay attacks
- Secure enclave environment for computation
- Decentralized MPC nodes with no single point of failure

### Role Credentials (Certificate NFT)

AMOCA Telemedicine enforces professional access via certificate NFTs:

- A credential NFT is a standard SPL Token (0 decimals) minted per role (doctor, nurse, pharmacist).
- Callers must present a token account holding at least 1 unit of the credential mint to perform role-gated actions.
- The program verifies: token account owner is the signer, token account mint equals the provided credential mint, amount ≥ 1, and mint has 0 decimals.

Client apps may choose distinct mints per role. The role-specific convenience instructions are thin wrappers over the generic `share_patient_data_with_role` and are intended for UX clarity.

### Example Flow

The test file (`share_medical_records.ts`) demonstrates:

1. Computation definition initialization
2. Encrypted patient data storage
3. Secure data sharing with a receiver (optionally role-gated via credential NFT)
4. Verification through on-chain events

This example effectively showcases how Arcium's MPC solution enables:

- Decentralized computation without any single trusted party
- Privacy-preserving data sharing on public blockchains
- Secure handling of sensitive medical information
- Integration with existing blockchain infrastructure
- Practical implementation of complex privacy-preserving protocols
