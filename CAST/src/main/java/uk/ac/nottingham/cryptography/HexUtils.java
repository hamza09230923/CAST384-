package uk.ac.nottingham.cryptography;

import java.util.Random;

/**
 * Helper methods for converting hexadecimal strings to byte arrays,
 * int arrays, and back.
 * <br/>
 * Used within the test classes to provide most tests as
 * hex strings. May be useful to you in manually testing within
 * main().
 * <br/>
 * Do not edit this class.
 */
public class HexUtils {

    private static final Random rand = new Random();
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String intsToHex(int[] ints) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < ints.length; i++) {
            hexString.append(String.format("%08X ", ints[i]));
        }
        return hexString.toString();
    }

    public static String intsToHex2(int[] ints) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < ints.length; i++) {
            hexString.append(String.format("%02X       ", ints[i]));
        }
        return hexString.toString();
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String RandomHex(int byteCount) {
        byte[] bytes = new byte[byteCount];
        rand.nextBytes(bytes);
        return bytesToHex(bytes);
    }

    public static int XORArray(int[] a) {
        int x = 0;
        for (int j : a) {
            x ^= j;
        }
        return x;
    }

    public static int SumArray(int[] a) {
        int x = 0;
        for (int j : a) {
            x += j;
        }
        return x;
    }



}

