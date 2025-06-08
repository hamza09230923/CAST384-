package uk.ac.nottingham.cryptography;

import java.util.Arrays;

public class Main {

    /**
     * Entry point when this program is run directly. Not used within
     * the coursework, but is available for those who would like to
     * test or debug themselves. Nothing in this file will be marked.
     *
     * @param args Command line arguments - not used in this coursework
     */
    public static void main(String[] args) {
        CAST384 cipher = new CAST384();

        // Define a 192-bit plaintext block (24 bytes) as hex
        byte[] plaintext = HexUtils.hexToBytes("000102030001020308090A0B08090A0B1011121310111213");
        System.out.println("Original : " + HexUtils.bytesToHex(plaintext));

        // Clone it before encryption to preserve the original
        byte[] toEncrypt = plaintext.clone();

        // Use a 384-bit key (all zeros here, or try a random one)
        byte[] key = new byte[48];
        cipher.initialise(key);

        // Encrypt (in-place)
        cipher.encrypt(toEncrypt);
        System.out.println("Encrypted: " + HexUtils.bytesToHex(toEncrypt));

        // Clone the ciphertext for decryption
        byte[] toDecrypt = toEncrypt.clone();
        cipher.decrypt(toDecrypt);
        System.out.println("Decrypted: " + HexUtils.bytesToHex(toDecrypt));

        // Verify recovered plaintext matches original
        System.out.println("Match?    : " + Arrays.equals(toDecrypt, plaintext));
    }


    }


    // You can add testing code here


