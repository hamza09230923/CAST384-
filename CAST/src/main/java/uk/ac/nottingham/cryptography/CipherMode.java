package uk.ac.nottingham.cryptography;

/**
 * Abstract class that partially implements a CipherMode. The class defines
 * simple initialisation, encrypt and decrypt functions.
 * <br/>
 * Do not edit this file.
 */
public abstract class CipherMode {
    protected Cipher cipher;

    public Cipher getCipher()
    {
        return cipher;
    }

    public CipherMode() {

    }

    public abstract void initialise(Cipher cipher, byte[] key, byte[] nonce);

    public abstract void encrypt(byte[] data);

    public abstract void decrypt(byte[] data);

    public abstract void seek(byte[] counter);
}
