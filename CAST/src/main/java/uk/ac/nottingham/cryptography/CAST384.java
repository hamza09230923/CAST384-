package uk.ac.nottingham.cryptography;

/**
 * Implementation of CASTCipher that encrypts and decrypts using the
 * CAST-384 algorithm.
 * @author Hamza
 */
public class CAST384 extends CASTCipher {

    // The computed round keys are stored in the inherited field K (of type CASTKeySet)
    // which contains two arrays which is one for masking keys (Km) and one for rotation keys (Kr).

    private static final int BLOCK_WORDS = 6;    // 192-bit block => 6 x 32-bit words
    private static final int KEY_WORDS = 12;       // 384-bit key => 12 x 32-bit words
    private static final int ROUNDS = 12;          // 12 rounds
    private static final int DODECAD_COUNT = 4;    // 4 dodecad calls per round

    /**
     * Default constructor.
     * Calls the parent constructor with key size of 192 bits (block) and 384 bits (key).
     */
    public CAST384() {
        super(192, 384);
    }

    /**
     * Initialises the cipher with the provided key.
     * How it works:
     * The key (which may be less than 384 bits) is padded with zeros to form a 384-bit key.
     * Then the key schedule is performed: which first generates the temporary keys (Tm, Tr),
     * then generates the round keys which is then used during encryption and decryption.
     * The number of rounds is fixed at 12.
     * @param key the secret key as a byte array.
     */
    @Override
    public void initialise(byte[] key) {
        // Pad key to 48 bytes (384 bits) if necessary.
        byte[] paddedKey = new byte[48];
        int len = Math.min(key.length, 48);
        System.arraycopy(key, 0, paddedKey, 0, len);

        // Generate temporary key schedule keys Tm and Tr (Algorithm 2)
        CASTKeySet tempSchedule = generateScheduleKeys(ROUNDS, DODECAD_COUNT);

        // Generate round keys using the dodecad function (Algorithm 1)
        CASTKeySet roundKeys = generateRoundKeys(tempSchedule, paddedKey, ROUNDS, DODECAD_COUNT);

        // Store the computed round keys in the inherited field K.
        this.K = roundKeys;
    }

    /**
     * Generates the temporary masking (Tm) and rotation (Tr) keys for the key schedule.
     * How it works:
     * This method implements Algorithm 2 from the CAST-384 specification. It is used to
     * populate two flattened arrays (Tm and Tr) with constants derived from a simple linear
     * recurrence which is then used to drive key mixing via the dodecad function.
     *
     * The total number of keys generated is: (rounds × dodecadCount × 12), where each dodecad
     * uses 12 masking and 12 rotation values.
     *
     * Constants used:
     *   - cm = 0x5A827999, incremented by Δm = 0x6ED9EBA1 each step (mod 2³²)
     *   - cr = 19, incremented by Δr = 17 each step (mod 32)
     *
     * @param roundCount    Number of encryption rounds (fixed at 12).
     * @param dodecadCount  Number of dodecad operations per round (fixed at 4).
     * @return              CASTKeySet that contains temporary keys Tm and Tr, both flattened arrays.
     */
    @Override
    public CASTKeySet generateScheduleKeys(int roundCount, int dodecadCount) {
        int total = roundCount * dodecadCount;  // Total number of dodecad iterations (e.g. 12×4 = 48)
        int len = total * KEY_WORDS;            // Total values = 48 × 12 = 576 entries per array

        int[] Tm = new int[len];  // Masking keys
        int[] Tr = new int[len];  // Rotation keys

        // Initialize constants per Algorithm 2
        int cm = 0x5A827999;        // Initial value for masking key
        int deltaM = 0x6ED9EBA1;     // Step size for cm (Δm)
        int cr = 19;                 // Initial value for rotation key
        int deltaR = 17;             // Step size for cr (Δr)

        // Populate Tm and Tr using linear recurrences
        for (int i = 0; i < total; i++) {
            for (int j = 0; j < KEY_WORDS; j++) {
                int index = i * KEY_WORDS + j;

                Tm[index] = cm;      // Store current masking key
                cm += deltaM;        // Advance masking key

                Tr[index] = cr;      // Store current rotation key
                cr = (cr + deltaR) % 32; // Advance and wrap rotation key to [0, 31]
            }
        }

        return new CASTKeySet(Tm, Tr);
    }

    /**
     * Generates the encryption and decryption round keys from the provided key material.
     * <p>
     * This method implements Algorithm 1 from the CAST-384 specification. This transforms
     * the 384-bit user key (κ) into 12 × 6 pairs of round keys (Km, Kr) by using multiple
     * dodecad operations. These round keys are then used to drive the six F-functions across 12 rounds.
     *
     * Key steps to this:
     *  - Convert the padded byte array into 12 32-bit words (κ = [A, B, ..., L]).
     *  - Apply the dodecad() function 4 times per round to mix κ.
     *  - Extract 6 masking and 6 rotation keys per round from specific positions in k.
     *
     * @param T             Temporary key material Tm and Tr, which is generated by generateScheduleKeys().
     * @param key           The padded 384-bit (48-byte) input key.
     * @param roundCount    Number of rounds (fixed at 12).
     * @param dodecadCount  Number of dodecad calls per round (fixed at 4).
     * @return              A CASTKeySet containing the round masking (Km) and rotation (Kr) keys.
     */
    @Override
    public CASTKeySet generateRoundKeys(CASTKeySet T, byte[] key, int roundCount, int dodecadCount) {
        // Ensure the key is padded to 48 bytes (384 bits), as required by CAST-384.
        byte[] paddedKey = new byte[48];
        System.arraycopy(key, 0, paddedKey, 0, Math.min(key.length, 48));
        // Convert the 48-byte key into 12 32-bit big-endian words: κ = [A, B, C, ..., L]
        int[] kappa = new int[KEY_WORDS];
        for (int i = 0; i < KEY_WORDS; i++) {
            int base = i * 4;
            kappa[i] = ((paddedKey[base] & 0xFF) << 24)
                    | ((paddedKey[base + 1] & 0xFF) << 16)
                    | ((paddedKey[base + 2] & 0xFF) << 8)
                    | (paddedKey[base + 3] & 0xFF);
        }
        // Allocate output round key arrays:
        // Each round produces 6 masking keys (Km) and 6 rotation keys (Kr).
        int[] Km = new int[roundCount * 6];
        int[] Kr = new int[roundCount * 6];
        // For each round, apply the dodecad function multiple times, then extract keys.
        for (int i = 0; i < roundCount; i++) {
            for (int d = 0; d < dodecadCount; d++) {
                // Compute flat offset into Tm/Tr (each dodecad uses 12 values).
                int offset = (i * dodecadCount + d) * KEY_WORDS;
                dodecad(kappa, T.getM(), T.getR(), offset);
            }
            // After mixing κ through dodecad, extract round keys as defined in the cw spec:
            //   Km: [L, J, H, F, D, B]      (positions 11, 9, 7, 5, 3, 1)
            //   Kr: [A, C, E, G, I, K] % 32 (positions 0, 2, 4, 6, 8, 10)
            int baseRK = i * 6;
            Km[baseRK + 0] = kappa[11];      // L
            Km[baseRK + 1] = kappa[9];       // J
            Km[baseRK + 2] = kappa[7];       // H
            Km[baseRK + 3] = kappa[5];       // F
            Km[baseRK + 4] = kappa[3];       // D
            Km[baseRK + 5] = kappa[1];       // B

            Kr[baseRK + 0] = kappa[0]  & 0x1F; // A mod 32
            Kr[baseRK + 1] = kappa[2]  & 0x1F; // C mod 32
            Kr[baseRK + 2] = kappa[4]  & 0x1F; // E mod 32
            Kr[baseRK + 3] = kappa[6]  & 0x1F; // G mod 32
            Kr[baseRK + 4] = kappa[8]  & 0x1F; // I mod 32
            Kr[baseRK + 5] = kappa[10] & 0x1F; // K mod 32
        }

        return new CASTKeySet(Km, Kr);
    }
    /**
     * Applies the dodecad function to a 12-word key block (κ), used in the key schedule phase.
     * How it works:
     * Defined in Algorithm 1 of the specification, this function performs 12 sequential
     * transformations using the six F-functions. The transformations then modify the internal state of κ
     * by using key-dependent and round-dependent values from the Tm and Tr arrays.
     *
     * The purpose of dodecad is to non-linearly diffuse and mix the working key block (κ)
     * in preparation for round key extraction. Each dodecad call is then applied 4 times per round.
     *
     * @param block the current working 12-word block κ = [A, B, ..., L] (index 0–11)
     * @param Tm    temporary masking keys (flattened array from generateScheduleKeys)
     * @param Tr    temporary rotation keys (flattened array from generateScheduleKeys)
     * @param idx   index offset into Tm/Tr (should point to 12 consecutive values for this dodecad)
     */
    @Override
    public void dodecad(int[] block, int[] Tm, int[] Tr, int idx) {
        // Step 1: K = K ⊕ F1(L, Tm[0], Tr[0])
        block[10] ^= f1(block[11], Tm[idx + 0], Tr[idx + 0]);

        // Step 2: J = J ⊕ F2(K, Tm[1], Tr[1])
        block[9]  ^= f2(block[10], Tm[idx + 1], Tr[idx + 1]);

        // Step 3: I = I ⊕ F3(J, Tm[2], Tr[2])
        block[8]  ^= f3(block[9], Tm[idx + 2], Tr[idx + 2]);

        // Step 4: H = H ⊕ F4(I, Tm[3], Tr[3])
        block[7]  ^= f4(block[8], Tm[idx + 3], Tr[idx + 3]);

        // Step 5: G = G ⊕ F5(H, Tm[4], Tr[4])
        block[6]  ^= f5(block[7], Tm[idx + 4], Tr[idx + 4]);

        // Step 6: F = F ⊕ F6(G, Tm[5], Tr[5])
        block[5]  ^= f6(block[6], Tm[idx + 5], Tr[idx + 5]);

        // Step 7: E = E ⊕ F1(F, Tm[6], Tr[6])
        block[4]  ^= f1(block[5], Tm[idx + 6], Tr[idx + 6]);

        // Step 8: D = D ⊕ F2(E, Tm[7], Tr[7])
        block[3]  ^= f2(block[4], Tm[idx + 7], Tr[idx + 7]);

        // Step 9: C = C ⊕ F3(D, Tm[8], Tr[8])
        block[2]  ^= f3(block[3], Tm[idx + 8], Tr[idx + 8]);

        // Step 10: B = B ⊕ F4(C, Tm[9], Tr[9])
        block[1]  ^= f4(block[2], Tm[idx + 9], Tr[idx + 9]);

        // Step 11: A = A ⊕ F5(B, Tm[10], Tr[10])
        block[0]  ^= f5(block[1], Tm[idx + 10], Tr[idx + 10]);

        // Step 12: L = L ⊕ F6(A, Tm[11], Tr[11])
        block[11] ^= f6(block[0], Tm[idx + 11], Tr[idx + 11]);
    }


    /**
     * Applies one forward hexad round on a 192-bit block using round keys.
     * How it works:
     * Follows the structure defined in Figure 4 of the specification.
     * Each step applies an F-function to a word and XORs it with another word in the block.
     * This forms the primary transformation in encryption rounds 0 to 5.
     *
     * The order of operations ensures data dependencies match the specification:
     *   E = E ⊕ F1(F), D = D ⊕ F2(E), ..., A = A ⊕ F5(B), F = F ⊕ F6(A)
     *
     * @param block the 6-word (192-bit) data block
     * @param Km    round masking keys
     * @param Kr    round rotation keys
     * @param idx   starting index into Km and Kr for this round (6 per round)
     */
    @Override
    public void hexad(int[] block, int[] Km, int[] Kr, int idx) {
        block[4] ^= f1(block[5], Km[idx], Kr[idx]);         // E = E ⊕ F1(F)
        block[3] ^= f2(block[4], Km[idx + 1], Kr[idx + 1]); // D = D ⊕ F2(E)
        block[2] ^= f3(block[3], Km[idx + 2], Kr[idx + 2]); // C = C ⊕ F3(D)
        block[1] ^= f4(block[2], Km[idx + 3], Kr[idx + 3]); // B = B ⊕ F4(C)
        block[0] ^= f5(block[1], Km[idx + 4], Kr[idx + 4]); // A = A ⊕ F5(B)
        block[5] ^= f6(block[0], Km[idx + 5], Kr[idx + 5]); // F = F ⊕ F6(A)
    }

    /**
     * Applies one inverse hexad round on a 192-bit block using round keys.
     * How it works:
     * Follows the reverse structure shown in Figure 5 of the specification.
     * This function is used in encryption rounds 6–11, and in decryption rounds 0–5.
     * It precisely undoes the effect of the forward hexad by reversing both the data and key order.
     *
     * The reversal order ensures reversibility of the cipher:
     *   F = F ⊕ F6(A), A = A ⊕ F5(B), ..., E = E ⊕ F1(F)
     *
     * @param block the 6-word (192-bit) data block
     * @param Km    round masking keys
     * @param Kr    round rotation keys
     * @param idx   starting index into Km and Kr for this round (6 per round)
     */
    @Override
    public void hexadInv(int[] block, int[] Km, int[] Kr, int idx) {
        block[5] ^= f6(block[0], Km[idx + 5], Kr[idx + 5]); // F = F ⊕ F6(A)
        block[0] ^= f5(block[1], Km[idx + 4], Kr[idx + 4]); // A = A ⊕ F5(B)
        block[1] ^= f4(block[2], Km[idx + 3], Kr[idx + 3]); // B = B ⊕ F4(C)
        block[2] ^= f3(block[3], Km[idx + 2], Kr[idx + 2]); // C = C ⊕ F3(D)
        block[3] ^= f2(block[4], Km[idx + 1], Kr[idx + 1]); // D = D ⊕ F2(E)
        block[4] ^= f1(block[5], Km[idx], Kr[idx]);         // E = E ⊕ F1(F)
    }

    /**
     * Encrypts a single 192-bit data block using 12 rounds of CAST-384.
     * <p>
     * According to the CAST-384 specification, the encryption process consists of:
     *   - 6 forward hexad rounds (Rounds 0 to 5 using hexad())
     *   - 6 inverse hexad rounds (Rounds 6 to 11 using hexadInv())
     *
     * The round keys (Km and Kr) are derived during key schedule setup.
     *
     * @param data 24-byte plaintext block (in-place encryption)
     */
    @Override
    public void encrypt(byte[] data) {
        int[] block = bytesToBlock(data);
        int[] Km = K.getM();
        int[] Kr = K.getR();

        // Apply forward hexad rounds (0 to 5)
        for (int i = 0; i < 6; i++) {
            hexad(block, Km, Kr, i * 6);
        }

        // Apply inverse hexad rounds (6 to 11)
        for (int i = 6; i < 12; i++) {
            hexadInv(block, Km, Kr, i * 6);
        }

        blockToBytes(block, data);
    }

    /**
     * Decrypts a single 192-bit ciphertext block using 12 rounds of CAST-384.
     * How it works:
     * Decryption should mirror encryption:
     *   - The inverse hexads (Rounds 11 to 6) use the hexad() function.
     *   - The forward hexads (Rounds 5 to 0) use the hexadInv() function.
     *
     * This reversal ensures that each transformation is undone exactly in reverse order.
     *
     * @param data 24-byte ciphertext block
     */
    @Override
    public void decrypt(byte[] data) {
        int[] block = bytesToBlock(data);
        int[] Km = K.getM();
        int[] Kr = K.getR();

        // Inverse hexad rounds (Rounds 11 to 6)
        for (int i = 11; i >= 6; i--) {
            hexad(block, Km, Kr, i * 6);
        }

        // Forward hexad rounds (Rounds 5 to 0)
        for (int i = 5; i >= 0; i--) {
            hexadInv(block, Km, Kr, i * 6);
        }

        blockToBytes(block, data);
    }


    // ---------------------------------------- F Functions ----------------------------------------------------

    /**
     * F1 Function: α = ADD, β = SUB, γ = XOR
     * Performs the transformation: ((S1[I1] ^ S2[I2]) - S3[I3]) + S4[I4]
     *
     * @param d 32-bit input word from data
     * @param Km 32-bit masking key
     * @param Kr rotation amount (0–31)
     * @return 32-bit result of F1 transformation
     */
    @Override
    public int f1(int d, int Km, int Kr) {
        int tmp = Integer.rotateLeft(d + Km, Kr);
        int b0 = (tmp >>> 24) & 0xFF;
        int b1 = (tmp >>> 16) & 0xFF;
        int b2 = (tmp >>> 8) & 0xFF;
        int b3 = tmp & 0xFF;
        return ((S1[b0] ^ S2[b1]) - S3[b2]) + S4[b3];
    }

    /**
     * F2 Function: α = XOR, β = ADD, γ = SUB
     * Performs the transformation: ((S1[I1] - S2[I2]) + S3[I3]) ^ S4[I4]
     *
     * @param d 32-bit input word from data
     * @param Km 32-bit masking key
     * @param Kr rotation amount (0–31)
     * @return 32-bit result of F2 transformation
     */
    @Override
    public int f2(int d, int Km, int Kr) {
        int tmp = Integer.rotateLeft(d ^ Km, Kr);
        int b0 = (tmp >>> 24) & 0xFF;
        int b1 = (tmp >>> 16) & 0xFF;
        int b2 = (tmp >>> 8) & 0xFF;
        int b3 = tmp & 0xFF;
        return ((S1[b0] - S2[b1]) + S3[b2]) ^ S4[b3];
    }

    /**
     * F3 Function: α = SUB, β = XOR, γ = ADD
     * Performs the transformation: ((S1[I1] + S2[I2]) ^ S3[I3]) - S4[I4]
     *
     * @param d 32-bit input word from data
     * @param Km 32-bit masking key
     * @param Kr rotation amount (0–31)
     * @return 32-bit result of F3 transformation
     */
    @Override
    public int f3(int d, int Km, int Kr) {
        int tmp = Integer.rotateLeft(Km - d, Kr);
        int b0 = (tmp >>> 24) & 0xFF;
        int b1 = (tmp >>> 16) & 0xFF;
        int b2 = (tmp >>> 8) & 0xFF;
        int b3 = tmp & 0xFF;
        return ((S1[b0] + S2[b1]) ^ S3[b2]) - S4[b3];
    }

    /**
     * F4 Function: α = SUB, β = ADD, γ = XOR
     * Performs the transformation: ((S1[I1] ^ S2[I2]) + S3[I3]) - S4[I4]
     *
     * @param d 32-bit input word from data
     * @param Km 32-bit masking key
     * @param Kr rotation amount (0–31)
     * @return 32-bit result of F4 transformation
     */
    @Override
    public int f4(int d, int Km, int Kr) {
        int tmp = Integer.rotateLeft(Km - d, Kr);
        int b0 = (tmp >>> 24) & 0xFF;
        int b1 = (tmp >>> 16) & 0xFF;
        int b2 = (tmp >>> 8) & 0xFF;
        int b3 = tmp & 0xFF;
        return ((S1[b0] ^ S2[b1]) + S3[b2]) - S4[b3];
    }

    /**
     * F5 Function: α = ADD, β = XOR, γ = SUB
     * Performs the transformation: ((S1[I1] - S2[I2]) ^ S3[I3]) + S4[I4]
     *
     * @param d 32-bit input word from data
     * @param Km 32-bit masking key
     * @param Kr rotation amount (0–31)
     * @return 32-bit result of F5 transformation
     */
    @Override
    public int f5(int d, int Km, int Kr) {
        int tmp = Integer.rotateLeft(d + Km, Kr);
        int b0 = (tmp >>> 24) & 0xFF;
        int b1 = (tmp >>> 16) & 0xFF;
        int b2 = (tmp >>> 8) & 0xFF;
        int b3 = tmp & 0xFF;
        return ((S1[b0] - S2[b1]) ^ S3[b2]) + S4[b3];
    }

    /**
     * F6 Function: α = XOR, β = SUB, γ = ADD
     * Performs the transformation: ((S1[I1] + S2[I2]) - S3[I3]) ^ S4[I4]
     *
     * @param d 32-bit input word from data
     * @param Km 32-bit masking key
     * @param Kr rotation amount (0–31)
     * @return 32-bit result of F6 transformation
     */
    @Override
    public int f6(int d, int Km, int Kr) {
        int tmp = Integer.rotateLeft(d ^ Km, Kr);
        int b0 = (tmp >>> 24) & 0xFF;
        int b1 = (tmp >>> 16) & 0xFF;
        int b2 = (tmp >>> 8) & 0xFF;
        int b3 = tmp & 0xFF;
        return ((S1[b0] + S2[b1]) - S3[b2]) ^ S4[b3];
    }

    /**
     * Converts a 192-bit byte array (24 bytes) into a 6-element int array.
     * How it works:
     * Each group of 4 bytes is interpreted as a big-endian 32-bit word.
     * This representation is used for processing 6×32-bit data blocks
     * within the CAST-384 encryption and decryption rounds.
     *
     * @param data the 24-byte input block (big-endian order)
     * @return an array of 6 integers representing the 192-bit block
     */
    private int[] bytesToBlock(byte[] data) {
        int[] block = new int[6];
        for (int i = 0; i < 6; i++) {
            int offset = i * 4;
            block[i] = ((data[offset] & 0xFF) << 24) |
                    ((data[offset + 1] & 0xFF) << 16) |
                    ((data[offset + 2] & 0xFF) << 8) |
                    (data[offset + 3] & 0xFF);
        }
        return block;
    }

    /**
     * Converts a 6-element int array (192 bits) into a 24-byte array.
     * How it works:
     * Each integer is written in big-endian order back to the byte array.
     * This will ensure compatibility with the block structure expected by
     * external systems and test vectors.
     *
     * @param block the 6-integer array representing a 192-bit data block
     * @param data the output byte array (must be at least 24 bytes long)
     */
    private void blockToBytes(int[] block, byte[] data) {
        for (int i = 0; i < 6; i++) {
            int offset = i * 4;
            data[offset]     = (byte)(block[i] >>> 24);
            data[offset + 1] = (byte)(block[i] >>> 16);
            data[offset + 2] = (byte)(block[i] >>> 8);
            data[offset + 3] = (byte) block[i];
        }
    }
}

