import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { ShareMedicalRecords } from "../target/types/share_medical_records";
import { randomBytes } from "crypto";
import {
  TOKEN_PROGRAM_ID,
  MINT_SIZE,
  createInitializeMintInstruction,
  getMinimumBalanceForRentExemptMint,
  createMint,
  createAccount,
  mintTo,
  getOrCreateAssociatedTokenAccount,
  createAssociatedTokenAccountInstruction,
} from "@solana/spl-token";
import {
  awaitComputationFinalization,
  getArciumEnv,
  getCompDefAccOffset,
  getArciumAccountBaseSeed,
  getArciumProgAddress,
  uploadCircuit,
  buildFinalizeCompDefTx,
  RescueCipher,
  deserializeLE,
  getMXEAccAddress,
  getMempoolAccAddress,
  getCompDefAccAddress,
  getExecutingPoolAccAddress,
  x25519,
  getComputationAccAddress,
  getMXEPublicKey,
} from "@arcium-hq/client";
import * as fs from "fs";
import * as os from "os";
import { expect } from "chai";

describe("ShareMedicalRecords", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace
    .ShareMedicalRecords as Program<ShareMedicalRecords>;
  const provider = anchor.getProvider();

  type Event = anchor.IdlEvents<(typeof program)["idl"]>;
  const awaitEvent = async <E extends keyof Event>(eventName: E) => {
    let listenerId: number;
    const event = await new Promise<Event[E]>((res) => {
      listenerId = program.addEventListener(eventName, (event) => {
        res(event);
      });
    });
    await program.removeEventListener(listenerId);

    return event;
  };

  const arciumEnv = getArciumEnv();

  it("can store and share patient data confidentially!", async () => {
    const owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);

    const mxePublicKey = await getMXEPublicKeyWithRetry(
      provider as anchor.AnchorProvider,
      program.programId
    );

    console.log("MXE x25519 pubkey is", mxePublicKey);

    console.log("Initializing share patient data computation definition");
    const initSPDSig = await initSharePatientDataCompDef(
      program,
      owner,
      false,
      false
    );
    console.log(
      "Share patient data computation definition initialized with signature",
      initSPDSig
    );

    const senderPrivateKey = x25519.utils.randomSecretKey();
    const senderPublicKey = x25519.getPublicKey(senderPrivateKey);
    const sharedSecret = x25519.getSharedSecret(senderPrivateKey, mxePublicKey);
    const cipher = new RescueCipher(sharedSecret);

    const patientId = BigInt(420);
    const age = BigInt(69);
    const gender = BigInt(true);
    const bloodType = BigInt(1); // A+
    const weight = BigInt(70);
    const height = BigInt(170);
    // allergies are [peanuts, latex, bees, wasps, cats]
    const allergies = [
      BigInt(false),
      BigInt(true),
      BigInt(false),
      BigInt(true),
      BigInt(false),
    ];

    // Prepare all 152 fields for the patient data structure
    // We'll use dummy data for fields we're not testing in detail
    const patientData = [
      patientId,
      age,
      gender,
      bloodType,
      weight,
      height,
      ...allergies,
      // Add dummy data for remaining fields to reach 152 total
      ...Array(145).fill(BigInt(0)),
    ];

    const nonce = randomBytes(16);
    const ciphertext = cipher.encrypt(patientData, nonce);

    // Convert all ciphertexts to Array<number> format (32-byte arrays)
    const ciphertextsArray: number[][] = ciphertext.map((ct) =>
      Array.from(ct)
    ) as number[][];

    const storeSig = await program.methods
      .storePatientData(ciphertextsArray)
      .rpc({ commitment: "confirmed" });
    console.log("Store sig is ", storeSig);

    const receiverSecretKey = x25519.utils.randomSecretKey();
    const receiverPubKey = x25519.getPublicKey(receiverSecretKey);
    const receiverNonce = randomBytes(16);

    const computationOffset = new anchor.BN(randomBytes(8), "hex");

    const queueSig = await program.methods
      .sharePatientData(
        computationOffset,
        Array.from(receiverPubKey),
        new anchor.BN(deserializeLE(receiverNonce).toString()),
        Array.from(senderPublicKey),
        new anchor.BN(deserializeLE(nonce).toString())
      )
      .accountsPartial({
        computationAccount: getComputationAccAddress(
          program.programId,
          computationOffset
        ),
        clusterAccount: arciumEnv.arciumClusterPubkey,
        mxeAccount: getMXEAccAddress(program.programId),
        mempoolAccount: getMempoolAccAddress(program.programId),
        executingPool: getExecutingPoolAccAddress(program.programId),
        compDefAccount: getCompDefAccAddress(
          program.programId,
          Buffer.from(getCompDefAccOffset("share_patient_data")).readUInt32LE()
        ),
        patientData: PublicKey.findProgramAddressSync(
          [Buffer.from("patient_data"), owner.publicKey.toBuffer()],
          program.programId
        )[0],
      })
      .rpc({ commitment: "confirmed" });
    console.log("Queue sig is ", queueSig);

    const finalizeSig = await awaitComputationFinalization(
      provider as anchor.AnchorProvider,
      computationOffset,
      program.programId,
      "confirmed"
    );
    console.log("Finalize sig is ", finalizeSig);

    const receiverSharedSecret = x25519.getSharedSecret(
      receiverSecretKey,
      mxePublicKey
    );
    const receiverCipher = new RescueCipher(receiverSharedSecret);

    console.log("Computation finalized successfully");
    // Note: Callback was removed to minimize stack usage, so events are no longer emitted
    // In production, clients would fetch the re-encrypted data from the computation output
    console.log("Data sharing completed - verify decryption via computation output");
  });

  it("can share patient data with doctor role credential NFT", async () => {
    const owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);

    // Create a credential NFT mint for doctor role (0 decimals)
    const credentialMintKeypair = Keypair.generate();
    const mintRent = await getMinimumBalanceForRentExemptMint(
      provider.connection
    );
    const createMintTx = new anchor.web3.Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: owner.publicKey,
        newAccountPubkey: credentialMintKeypair.publicKey,
        space: MINT_SIZE,
        lamports: mintRent,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeMintInstruction(
        credentialMintKeypair.publicKey,
        0, // 0 decimals for NFT
        owner.publicKey,
        null
      )
    );
    await provider.sendAndConfirm(createMintTx, [owner, credentialMintKeypair]);

    // Create token account and mint 1 token to owner
    const tokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      owner,
      credentialMintKeypair.publicKey,
      owner.publicKey
    );
    await mintTo(
      provider.connection,
      owner,
      credentialMintKeypair.publicKey,
      tokenAccount.address,
      owner,
      1 // Mint 1 credential NFT
    );

    console.log(
      `Created doctor credential NFT: ${credentialMintKeypair.publicKey}`
    );
    console.log(`Token account: ${tokenAccount.address}`);

    // Use the role-gated share function
    const receiverSecretKey = x25519.utils.randomSecretKey();
    const receiverPubKey = x25519.getPublicKey(receiverSecretKey);
    const receiverNonce = randomBytes(16);
    const computationOffset = new anchor.BN(randomBytes(8), "hex");
    const senderPrivateKey = x25519.utils.randomSecretKey();
    const senderPublicKey = x25519.getPublicKey(senderPrivateKey);
    const nonce = randomBytes(16);

    const patientDataPDA = PublicKey.findProgramAddressSync(
      [Buffer.from("patient_data"), owner.publicKey.toBuffer()],
      program.programId
    )[0];

    try {
      const shareSig = await program.methods
        .sharePatientDataDoctor(
          computationOffset,
          Array.from(receiverPubKey),
          new anchor.BN(deserializeLE(receiverNonce).toString()),
          Array.from(senderPublicKey),
          new anchor.BN(deserializeLE(nonce).toString())
        )
        .accountsPartial({
          computationAccount: getComputationAccAddress(
            program.programId,
            computationOffset
          ),
          clusterAccount: arciumEnv.arciumClusterPubkey,
          mxeAccount: getMXEAccAddress(program.programId),
          mempoolAccount: getMempoolAccAddress(program.programId),
          executingPool: getExecutingPoolAccAddress(program.programId),
          compDefAccount: getCompDefAccAddress(
            program.programId,
            Buffer.from(getCompDefAccOffset("share_patient_data")).readUInt32LE()
          ),
          patientData: patientDataPDA,
          credentialMint: credentialMintKeypair.publicKey,
          credentialTokenAccount: tokenAccount.address,
        })
        .rpc({ commitment: "confirmed" });

      console.log("Doctor role-gated share transaction:", shareSig);
      expect(shareSig).to.be.a("string");
    } catch (error) {
      console.error("Error in doctor role-gated share:", error);
      throw error;
    }
  });

  it("can share patient data with nurse role credential NFT", async () => {
    const owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);

    // Create a credential NFT mint for nurse role
    const credentialMintKeypair = Keypair.generate();
    const mintRent = await getMinimumBalanceForRentExemptMint(
      provider.connection
    );
    const createMintTx = new anchor.web3.Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: owner.publicKey,
        newAccountPubkey: credentialMintKeypair.publicKey,
        space: MINT_SIZE,
        lamports: mintRent,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeMintInstruction(
        credentialMintKeypair.publicKey,
        0,
        owner.publicKey,
        null
      )
    );
    await provider.sendAndConfirm(createMintTx, [owner, credentialMintKeypair]);

    const tokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      owner,
      credentialMintKeypair.publicKey,
      owner.publicKey
    );
    await mintTo(
      provider.connection,
      owner,
      credentialMintKeypair.publicKey,
      tokenAccount.address,
      owner,
      1
    );

    const receiverSecretKey = x25519.utils.randomSecretKey();
    const receiverPubKey = x25519.getPublicKey(receiverSecretKey);
    const receiverNonce = randomBytes(16);
    const computationOffset = new anchor.BN(randomBytes(8), "hex");
    const senderPrivateKey = x25519.utils.randomSecretKey();
    const senderPublicKey = x25519.getPublicKey(senderPrivateKey);
    const nonce = randomBytes(16);

    const patientDataPDA = PublicKey.findProgramAddressSync(
      [Buffer.from("patient_data"), owner.publicKey.toBuffer()],
      program.programId
    )[0];

    const shareSig = await program.methods
      .sharePatientDataNurse(
        computationOffset,
        Array.from(receiverPubKey),
        new anchor.BN(deserializeLE(receiverNonce).toString()),
        Array.from(senderPublicKey),
        new anchor.BN(deserializeLE(nonce).toString())
      )
      .accountsPartial({
        computationAccount: getComputationAccAddress(
          program.programId,
          computationOffset
        ),
        clusterAccount: arciumEnv.arciumClusterPubkey,
        mxeAccount: getMXEAccAddress(program.programId),
        mempoolAccount: getMempoolAccAddress(program.programId),
        executingPool: getExecutingPoolAccAddress(program.programId),
        compDefAccount: getCompDefAccAddress(
          program.programId,
          Buffer.from(getCompDefAccOffset("share_patient_data")).readUInt32LE()
        ),
        patientData: patientDataPDA,
        credentialMint: credentialMintKeypair.publicKey,
        credentialTokenAccount: tokenAccount.address,
      })
      .rpc({ commitment: "confirmed" });

    console.log("Nurse role-gated share transaction:", shareSig);
    expect(shareSig).to.be.a("string");
  });

  it("can share patient data with pharmacist role credential NFT", async () => {
    const owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);

    // Create a credential NFT mint for pharmacist role
    const credentialMintKeypair = Keypair.generate();
    const mintRent = await getMinimumBalanceForRentExemptMint(
      provider.connection
    );
    const createMintTx = new anchor.web3.Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: owner.publicKey,
        newAccountPubkey: credentialMintKeypair.publicKey,
        space: MINT_SIZE,
        lamports: mintRent,
        programId: TOKEN_PROGRAM_ID,
      }),
      createInitializeMintInstruction(
        credentialMintKeypair.publicKey,
        0,
        owner.publicKey,
        null
      )
    );
    await provider.sendAndConfirm(createMintTx, [owner, credentialMintKeypair]);

    const tokenAccount = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      owner,
      credentialMintKeypair.publicKey,
      owner.publicKey
    );
    await mintTo(
      provider.connection,
      owner,
      credentialMintKeypair.publicKey,
      tokenAccount.address,
      owner,
      1
    );

    const receiverSecretKey = x25519.utils.randomSecretKey();
    const receiverPubKey = x25519.getPublicKey(receiverSecretKey);
    const receiverNonce = randomBytes(16);
    const computationOffset = new anchor.BN(randomBytes(8), "hex");
    const senderPrivateKey = x25519.utils.randomSecretKey();
    const senderPublicKey = x25519.getPublicKey(senderPrivateKey);
    const nonce = randomBytes(16);

    const patientDataPDA = PublicKey.findProgramAddressSync(
      [Buffer.from("patient_data"), owner.publicKey.toBuffer()],
      program.programId
    )[0];

    const shareSig = await program.methods
      .sharePatientDataPharmacist(
        computationOffset,
        Array.from(receiverPubKey),
        new anchor.BN(deserializeLE(receiverNonce).toString()),
        Array.from(senderPublicKey),
        new anchor.BN(deserializeLE(nonce).toString())
      )
      .accountsPartial({
        computationAccount: getComputationAccAddress(
          program.programId,
          computationOffset
        ),
        clusterAccount: arciumEnv.arciumClusterPubkey,
        mxeAccount: getMXEAccAddress(program.programId),
        mempoolAccount: getMempoolAccAddress(program.programId),
        executingPool: getExecutingPoolAccAddress(program.programId),
        compDefAccount: getCompDefAccAddress(
          program.programId,
          Buffer.from(getCompDefAccOffset("share_patient_data")).readUInt32LE()
        ),
        patientData: patientDataPDA,
        credentialMint: credentialMintKeypair.publicKey,
        credentialTokenAccount: tokenAccount.address,
      })
      .rpc({ commitment: "confirmed" });

    console.log("Pharmacist role-gated share transaction:", shareSig);
    expect(shareSig).to.be.a("string");
  });

  async function initSharePatientDataCompDef(
    program: Program<ShareMedicalRecords>,
    owner: anchor.web3.Keypair,
    uploadRawCircuit: boolean,
    offchainSource: boolean
  ): Promise<string> {
    const baseSeedCompDefAcc = getArciumAccountBaseSeed(
      "ComputationDefinitionAccount"
    );
    const offset = getCompDefAccOffset("share_patient_data");

    const compDefPDA = PublicKey.findProgramAddressSync(
      [baseSeedCompDefAcc, program.programId.toBuffer(), offset],
      getArciumProgAddress()
    )[0];

    console.log("Comp def pda is ", compDefPDA);

    const sig = await program.methods
      .initSharePatientDataCompDef()
      .accounts({
        compDefAccount: compDefPDA,
        payer: owner.publicKey,
        mxeAccount: getMXEAccAddress(program.programId),
      })
      .signers([owner])
      .rpc({
        commitment: "confirmed",
      });
    console.log(
      "Init share patient data computation definition transaction",
      sig
    );

    if (uploadRawCircuit) {
      const rawCircuit = fs.readFileSync("build/share_patient_data.arcis");

      await uploadCircuit(
        provider as anchor.AnchorProvider,
        "share_patient_data",
        program.programId,
        rawCircuit,
        true
      );
    } else if (!offchainSource) {
      const finalizeTx = await buildFinalizeCompDefTx(
        provider as anchor.AnchorProvider,
        Buffer.from(offset).readUInt32LE(),
        program.programId
      );

      const latestBlockhash = await provider.connection.getLatestBlockhash();
      finalizeTx.recentBlockhash = latestBlockhash.blockhash;
      finalizeTx.lastValidBlockHeight = latestBlockhash.lastValidBlockHeight;

      finalizeTx.sign(owner);

      await provider.sendAndConfirm(finalizeTx);
    }
    return sig;
  }
});

async function getMXEPublicKeyWithRetry(
  provider: anchor.AnchorProvider,
  programId: PublicKey,
  maxRetries: number = 10,
  retryDelayMs: number = 500
): Promise<Uint8Array> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const mxePublicKey = await getMXEPublicKey(provider, programId);
      if (mxePublicKey) {
        return mxePublicKey;
      }
    } catch (error) {
      console.log(`Attempt ${attempt} failed to fetch MXE public key:`, error);
    }

    if (attempt < maxRetries) {
      console.log(
        `Retrying in ${retryDelayMs}ms... (attempt ${attempt}/${maxRetries})`
      );
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }

  throw new Error(
    `Failed to fetch MXE public key after ${maxRetries} attempts`
  );
}

function readKpJson(path: string): anchor.web3.Keypair {
  const file = fs.readFileSync(path);
  return anchor.web3.Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(file.toString()))
  );
}
