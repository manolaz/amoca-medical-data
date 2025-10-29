use arcis_imports::*;

#[encrypted]
mod circuits {
    use arcis_imports::*;

    pub struct PatientData {
        // Basic demographics
        pub patient_id: u64,
        pub age: u8,
        pub gender: bool,
        pub blood_type: u8,
        pub weight: u16,
        pub height: u16,
        pub allergies: [bool; 5],
        
        // Advanced Healthcare Data
        // Medical history: [diabetes, hypertension, heart_disease, cancer, stroke, asthma, copd, arthritis, osteoporosis, depression]
        pub medical_history: [bool; 10],
        // Current medications count (up to 8 medications tracked)
        pub medication_count: u8,
        // Medication IDs (simplified as u64 identifiers, up to 8)
        pub medications: [u64; 8],
        // Surgical procedures count
        pub procedure_count: u8,
        // Procedure dates (days since epoch, up to 8 procedures)
        pub procedure_dates: [u32; 8],
        // Family history: [diabetes, heart_disease, cancer, stroke, hypertension]
        pub family_history: [bool; 5],
        
        // Genomic Analysis Data
        // Genetic variant count (SNPs and variants)
        pub variant_count: u16,
        // Genetic markers (represented as u64 identifiers, up to 15 variants)
        pub genetic_markers: [u64; 15],
        // Variant significance scores (0-255 normalized, up to 15)
        pub variant_significance: [u8; 15],
        // Carrier status: [cystic_fibrosis, sickle_cell, tay_sachs, hemophilia, huntington]
        pub carrier_status: [bool; 5],
        // Pharmacogenomic markers: [warfarin_sensitivity, clopidogrel_resistance, statin_response]
        pub pharmacogenomic_markers: [bool; 3],
        // Ancestry components (percentages 0-100, up to 7 populations)
        pub ancestry_components: [u8; 7],
        
        // Lab Test Results
        // Lab test count
        pub lab_test_count: u8,
        // Test types: [cbc, lipid_panel, metabolic_panel, liver_function, kidney_function, thyroid, hba1c, psa]
        pub lab_test_types: [u8; 10],
        // Test dates (days since epoch, up to 10 tests)
        pub lab_test_dates: [u32; 10],
        // Test values (normalized 0-65535, up to 10 tests)
        pub lab_test_values: [u16; 10],
        // Normal range flags (0=low, 1=normal, 2=high, up to 10 tests)
        pub lab_test_flags: [u8; 10],
        // Imaging results count
        pub imaging_count: u8,
        // Imaging types: [xray, ct, mri, ultrasound, mammography]
        pub imaging_types: [u8; 10],
        // Imaging dates (days since epoch, up to 10)
        pub imaging_dates: [u32; 10],
    }

    #[instruction]
    pub fn share_patient_data(
        receiver: Shared,
        input_ctxt: Enc<Shared, PatientData>,
    ) -> Enc<Shared, PatientData> {
        let input = input_ctxt.to_arcis();
        receiver.from_arcis(input)
    }
}
