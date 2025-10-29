use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

const COMP_DEF_OFFSET_SHARE_PATIENT_DATA: u32 = comp_def_offset("share_patient_data");

declare_id!("NEnkfYAYz9epwXkXChP3hz2y1L8wUgf2xkrUKAmfxBD");

#[arcium_program]
pub mod share_medical_records {
    use super::*;
    use anchor_spl::token::{Mint, Token, TokenAccount};

    /// Stores encrypted patient medical data on-chain.
    ///
    /// This function stores comprehensive patient medical information in encrypted form, including
    /// basic demographics, advanced healthcare history, genomic analysis, and lab test results.
    /// All data fields are provided as encrypted 32-byte arrays that can only be decrypted by authorized parties.
    /// The data remains confidential while being stored on the public Solana blockchain.
    ///
    /// # Arguments
    /// Basic demographics: patient_id, age, gender, blood_type, weight, height, allergies
    /// Advanced healthcare: medical_history, medication_count, medications, procedure_count, 
    ///                      procedure_dates, family_history
    /// Genomic analysis: variant_count, genetic_markers, variant_significance, carrier_status,
    ///                   pharmacogenomic_markers, ancestry_components
    /// Lab test results: lab_test_count, lab_test_types, lab_test_dates, lab_test_values,
    ///                   lab_test_flags, imaging_count, imaging_types, imaging_dates
    pub fn store_patient_data(
        ctx: Context<StorePatientData>,
        ciphertexts: Vec<[u8; 32]>,
    ) -> Result<()> {
        // Expect 152 fields, indexed exactly as emitted in the callback
        if ciphertexts.len() != 152 {
            return Err(ErrorCode::InvalidInputLength.into());
        }

        let mut data = ctx.accounts.patient_data.load_init()?;

        // Basic demographics
        data.demographics.patient_id = ciphertexts[0];
        data.demographics.age = ciphertexts[1];
        data.demographics.gender = ciphertexts[2];
        data.demographics.blood_type = ciphertexts[3];
        data.demographics.weight = ciphertexts[4];
        data.demographics.height = ciphertexts[5];
        for i in 0..5 { data.demographics.allergies[i] = ciphertexts[6 + i]; }

        // Advanced healthcare
        for i in 0..10 { data.healthcare.medical_history[i] = ciphertexts[11 + i]; }
        data.healthcare.medication_count = ciphertexts[21];
        for i in 0..8 { data.healthcare.medications[i] = ciphertexts[22 + i]; }
        data.healthcare.procedure_count = ciphertexts[30];
        for i in 0..8 { data.healthcare.procedure_dates[i] = ciphertexts[31 + i]; }
        for i in 0..5 { data.healthcare.family_history[i] = ciphertexts[39 + i]; }

        // Genomic analysis
        data.genomic.variant_count = ciphertexts[44];
        for i in 0..15 { data.genomic.genetic_markers[i] = ciphertexts[45 + i]; }
        for i in 0..15 { data.genomic.variant_significance[i] = ciphertexts[60 + i]; }
        for i in 0..5 { data.genomic.carrier_status[i] = ciphertexts[75 + i]; }
        for i in 0..3 { data.genomic.pharmacogenomic_markers[i] = ciphertexts[80 + i]; }
        for i in 0..7 { data.genomic.ancestry_components[i] = ciphertexts[83 + i]; }

        // Lab test results
        data.lab_tests.lab_test_count = ciphertexts[90];
        for i in 0..10 { data.lab_tests.lab_test_types[i] = ciphertexts[91 + i]; }
        for i in 0..10 { data.lab_tests.lab_test_dates[i] = ciphertexts[101 + i]; }
        for i in 0..10 { data.lab_tests.lab_test_values[i] = ciphertexts[111 + i]; }
        for i in 0..10 { data.lab_tests.lab_test_flags[i] = ciphertexts[121 + i]; }
        data.lab_tests.imaging_count = ciphertexts[131];
        for i in 0..10 { data.lab_tests.imaging_types[i] = ciphertexts[132 + i]; }
        for i in 0..10 { data.lab_tests.imaging_dates[i] = ciphertexts[142 + i]; }

        Ok(())
    }

    pub fn init_share_patient_data_comp_def(
        ctx: Context<InitSharePatientDataCompDef>,
    ) -> Result<()> {
        init_comp_def(ctx.accounts, true, 0, None, None)?;
        Ok(())
    }

    /// Initiates confidential sharing of patient data with a specified receiver.
    ///
    /// This function triggers an MPC computation that re-encrypts the patient's medical data
    /// for a specific receiver. The receiver will be able to decrypt the data using their
    /// private key, while the data remains encrypted for everyone else. The original
    /// stored data is not modified and remains encrypted for the original owner.
    ///
    /// # Arguments
    /// * `receiver` - Public key of the authorized recipient
    /// * `receiver_nonce` - Cryptographic nonce for the receiver's encryption
    /// * `sender_pub_key` - Sender's public key for the operation
    /// * `nonce` - Cryptographic nonce for the sender's encryption
    pub fn share_patient_data(
        ctx: Context<SharePatientData>,
        computation_offset: u64,
        receiver: [u8; 32],
        receiver_nonce: u128,
        sender_pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        let args = vec![
            Argument::ArcisPubkey(receiver),
            Argument::PlaintextU128(receiver_nonce),
            Argument::ArcisPubkey(sender_pub_key),
            Argument::PlaintextU128(nonce),
            Argument::Account(
                ctx.accounts.patient_data.key(),
                8,
                core::mem::size_of::<PatientData>() as u32,
            ),
        ];

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![],
        )?;
        Ok(())
    }

    /// AMOCA Telemedicine: Role-gated share using a certificate NFT (SPL token with 0 decimals).
    pub fn share_patient_data_with_role(
        ctx: Context<SharePatientDataWithRole>,
        computation_offset: u64,
        receiver: [u8; 32],
        receiver_nonce: u128,
        sender_pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        // Verify credential token account belongs to signer, matches mint, and holds at least 1 token
        require_keys_eq!(ctx.accounts.credential_token_account.owner, ctx.accounts.payer.key(), ErrorCode::Unauthorized);
        require_keys_eq!(ctx.accounts.credential_token_account.mint, ctx.accounts.credential_mint.key(), ErrorCode::Unauthorized);
        require!(ctx.accounts.credential_mint.decimals == 0, ErrorCode::InvalidCredentialMint);
        require!(ctx.accounts.credential_token_account.amount >= 1, ErrorCode::MissingCredential);

        // Proceed with regular share
        let args = vec![
            Argument::ArcisPubkey(receiver),
            Argument::PlaintextU128(receiver_nonce),
            Argument::ArcisPubkey(sender_pub_key),
            Argument::PlaintextU128(nonce),
            Argument::Account(
                ctx.accounts.patient_data.key(),
                8,
                core::mem::size_of::<PatientData>() as u32,
            ),
        ];

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![],
        )?;
        Ok(())
    }

    /// Convenience: doctor role (uses provided credential mint/token account)
    pub fn share_patient_data_doctor(
        ctx: Context<SharePatientDataWithRole>,
        computation_offset: u64,
        receiver: [u8; 32],
        receiver_nonce: u128,
        sender_pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        share_patient_data_with_role(ctx, computation_offset, receiver, receiver_nonce, sender_pub_key, nonce)
    }

    /// Convenience: nurse role (uses provided credential mint/token account)
    pub fn share_patient_data_nurse(
        ctx: Context<SharePatientDataWithRole>,
        computation_offset: u64,
        receiver: [u8; 32],
        receiver_nonce: u128,
        sender_pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        share_patient_data_with_role(ctx, computation_offset, receiver, receiver_nonce, sender_pub_key, nonce)
    }

    /// Convenience: pharmacist role (uses provided credential mint/token account)
    pub fn share_patient_data_pharmacist(
        ctx: Context<SharePatientDataWithRole>,
        computation_offset: u64,
        receiver: [u8; 32],
        receiver_nonce: u128,
        sender_pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        share_patient_data_with_role(ctx, computation_offset, receiver, receiver_nonce, sender_pub_key, nonce)
    }

    // Callback removed to minimize stack usage
}

#[derive(Accounts)]
pub struct StorePatientData<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
    #[account(
        init,
        payer = payer,
        space = 8 + core::mem::size_of::<PatientData>(),
        seeds = [b"patient_data", payer.key().as_ref()],
        bump,
    )]
    pub patient_data: AccountLoader<'info, PatientData>,
}

#[queue_computation_accounts("share_patient_data", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct SharePatientData<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, SignerAccount>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(
        mut,
        address = derive_mempool_pda!()
    )]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_execpool_pda!()
    )]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_comp_pda!(computation_offset)
    )]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_SHARE_PATIENT_DATA)
    )]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Account<'info, Cluster>,
    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Account<'info, FeePool>,
    #[account(
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    pub patient_data: AccountLoader<'info, PatientData>,
}

#[queue_computation_accounts("share_patient_data", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct SharePatientDataWithRole<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, SignerAccount>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(
        mut,
        address = derive_mempool_pda!()
    )]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_execpool_pda!()
    )]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_comp_pda!(computation_offset)
    )]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_SHARE_PATIENT_DATA)
    )]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Account<'info, Cluster>,
    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Account<'info, FeePool>,
    #[account(
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    pub patient_data: AccountLoader<'info, PatientData>,

    // Credential NFT accounts
    pub credential_mint: Account<'info, anchor_spl::token::Mint>,
    #[account(
        constraint = credential_token_account.owner == payer.key() @ ErrorCode::Unauthorized,
        constraint = credential_token_account.mint == credential_mint.key() @ ErrorCode::Unauthorized,
    )]
    pub credential_token_account: Account<'info, anchor_spl::token::TokenAccount>,
    pub token_program: Program<'info, anchor_spl::token::Token>,
}

// SharePatientDataCallback accounts removed

#[init_computation_definition_accounts("share_patient_data", payer)]
#[derive(Accounts)]
pub struct InitSharePatientDataCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    /// Can't check it here as it's not initialized yet.
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

/// Basic patient demographics data event
#[event]
pub struct ReceivedBasicPatientDataEvent {
    pub nonce: [u8; 16],
    pub patient_id: [u8; 32],
    pub age: [u8; 32],
    pub gender: [u8; 32],
    pub blood_type: [u8; 32],
    pub weight: [u8; 32],
    pub height: [u8; 32],
    pub allergies: [[u8; 32]; 5],
}

/// Advanced healthcare data event (medical history, medications, procedures, family history)
#[event]
pub struct ReceivedHealthcareDataEvent {
    pub nonce: [u8; 16],
    pub medical_history: [[u8; 32]; 10],
    pub medication_count: [u8; 32],
    pub medications: [[u8; 32]; 8],
    pub procedure_count: [u8; 32],
    pub procedure_dates: [[u8; 32]; 8],
    pub family_history: [[u8; 32]; 5],
}

/// Genomic analysis data event (genetic variants, markers, carrier status, ancestry)
#[event]
pub struct ReceivedGenomicDataEvent {
    pub nonce: [u8; 16],
    pub variant_count: [u8; 32],
    pub genetic_markers: [[u8; 32]; 15],
    pub variant_significance: [[u8; 32]; 15],
    pub carrier_status: [[u8; 32]; 5],
    pub pharmacogenomic_markers: [[u8; 32]; 3],
    pub ancestry_components: [[u8; 32]; 7],
}

/// Lab test results and imaging data event
#[event]
pub struct ReceivedLabTestDataEvent {
    pub nonce: [u8; 16],
    pub lab_test_count: [u8; 32],
    pub lab_test_types: [[u8; 32]; 10],
    pub lab_test_dates: [[u8; 32]; 10],
    pub lab_test_values: [[u8; 32]; 10],
    pub lab_test_flags: [[u8; 32]; 10],
    pub imaging_count: [u8; 32],
    pub imaging_types: [[u8; 32]; 10],
    pub imaging_dates: [[u8; 32]; 10],
}

/// Basic patient demographics information
#[repr(C)]
pub struct BasicDemographics {
    /// Encrypted unique patient identifier
    pub patient_id: [u8; 32],
    /// Encrypted patient age
    pub age: [u8; 32],
    /// Encrypted gender information
    pub gender: [u8; 32],
    /// Encrypted blood type
    pub blood_type: [u8; 32],
    /// Encrypted weight measurement
    pub weight: [u8; 32],
    /// Encrypted height measurement
    pub height: [u8; 32],
    /// Array of encrypted allergy information (up to 5 allergies)
    pub allergies: [[u8; 32]; 5],
}

/// Advanced healthcare data including medical history, medications, procedures, and family history
#[repr(C)]
pub struct HealthcareData {
    /// Encrypted medical history flags (diabetes, hypertension, heart_disease, cancer, stroke, asthma, copd, arthritis, osteoporosis, depression)
    pub medical_history: [[u8; 32]; 10],
    /// Encrypted medication count
    pub medication_count: [u8; 32],
    /// Array of encrypted medication IDs (up to 8 medications)
    pub medications: [[u8; 32]; 8],
    /// Encrypted procedure count
    pub procedure_count: [u8; 32],
    /// Array of encrypted procedure dates (days since epoch, up to 8 procedures)
    pub procedure_dates: [[u8; 32]; 8],
    /// Encrypted family history flags (diabetes, heart_disease, cancer, stroke, hypertension)
    pub family_history: [[u8; 32]; 5],
}

/// Genomic analysis data including genetic variants, markers, carrier status, and ancestry
#[repr(C)]
pub struct GenomicData {
    /// Encrypted genetic variant count
    pub variant_count: [u8; 32],
    /// Array of encrypted genetic marker identifiers (up to 15 variants)
    pub genetic_markers: [[u8; 32]; 15],
    /// Array of encrypted variant significance scores (up to 15)
    pub variant_significance: [[u8; 32]; 15],
    /// Encrypted carrier status flags (cystic_fibrosis, sickle_cell, tay_sachs, hemophilia, huntington)
    pub carrier_status: [[u8; 32]; 5],
    /// Encrypted pharmacogenomic markers (warfarin_sensitivity, clopidogrel_resistance, statin_response)
    pub pharmacogenomic_markers: [[u8; 32]; 3],
    /// Array of encrypted ancestry component percentages (up to 7 populations)
    pub ancestry_components: [[u8; 32]; 7],
}

/// Lab test results and imaging data
#[repr(C)]
pub struct LabTestData {
    /// Encrypted lab test count
    pub lab_test_count: [u8; 32],
    /// Array of encrypted lab test type identifiers (up to 10 tests)
    pub lab_test_types: [[u8; 32]; 10],
    /// Array of encrypted lab test dates (days since epoch, up to 10 tests)
    pub lab_test_dates: [[u8; 32]; 10],
    /// Array of encrypted lab test values (normalized, up to 10 tests)
    pub lab_test_values: [[u8; 32]; 10],
    /// Array of encrypted lab test normal range flags (0=low, 1=normal, 2=high, up to 10 tests)
    pub lab_test_flags: [[u8; 32]; 10],
    /// Encrypted imaging count
    pub imaging_count: [u8; 32],
    /// Array of encrypted imaging type identifiers (up to 10 imaging studies)
    pub imaging_types: [[u8; 32]; 10],
    /// Array of encrypted imaging dates (days since epoch, up to 10)
    pub imaging_dates: [[u8; 32]; 10],
}

/// Stores encrypted patient medical information including advanced healthcare,
/// genomic analysis, and lab test results.
#[account(zero_copy)]
#[repr(C)]
pub struct PatientData {
    pub demographics: BasicDemographics,
    pub healthcare: HealthcareData,
    pub genomic: GenomicData,
    pub lab_tests: LabTestData,
}

#[error_code]
pub enum ErrorCode {
    #[msg("The computation was aborted")]
    AbortedComputation,
    #[msg("Invalid ciphertexts length")]
    InvalidInputLength,
    #[msg("Invalid allergy data format")]
    InvalidAllergyData,
    #[msg("Cluster not set")]
    ClusterNotSet,
    #[msg("Invalid medical history data format")]
    InvalidMedicalHistory,
    #[msg("Invalid medications data format")]
    InvalidMedications,
    #[msg("Invalid procedure dates data format")]
    InvalidProcedureDates,
    #[msg("Invalid family history data format")]
    InvalidFamilyHistory,
    #[msg("Invalid genetic markers data format")]
    InvalidGeneticMarkers,
    #[msg("Invalid variant significance data format")]
    InvalidVariantSignificance,
    #[msg("Invalid carrier status data format")]
    InvalidCarrierStatus,
    #[msg("Invalid pharmacogenomic markers data format")]
    InvalidPharmacogenomicMarkers,
    #[msg("Invalid ancestry components data format")]
    InvalidAncestryComponents,
    #[msg("Invalid lab test types data format")]
    InvalidLabTestTypes,
    #[msg("Invalid lab test dates data format")]
    InvalidLabTestDates,
    #[msg("Invalid lab test values data format")]
    InvalidLabTestValues,
    #[msg("Invalid lab test flags data format")]
    InvalidLabTestFlags,
    #[msg("Invalid imaging types data format")]
    InvalidImagingTypes,
    #[msg("Invalid imaging dates data format")]
    InvalidImagingDates,
    #[msg("Caller lacks required credential NFT")]
    MissingCredential,
    #[msg("Invalid credential mint (must be 0 decimals)")]
    InvalidCredentialMint,
    #[msg("Unauthorized or mismatched credential account")]
    Unauthorized,
}
