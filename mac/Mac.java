package stevens.cs306.mac;

import java.security.Key;

// Implement this class
public class Mac extends MacSkeleton {

    /**
     * Implement the mac and verify methods.  Mac should take a message and a
     * key (generated by the generate method) and return a tag.  Verify should
     * take a message, tag, and key -- and authenticate that the tag corresponds
     * to the message/tag pair by returning true or false.
     *
     * The following methods have been made available to you through the
     * MacSkeleton class:
     *
     * byte[] xor(byte[] a, byte[] b) :: XOR two byte arrays. Returns result
     * byte[] pad(byte[] message, int blockSz) :: pads message to blockSz
     * byte[] encryptBlock(byte[] block, Key key) :: Encrypts a single block
     * int getBlockSize() :: Returns the block size of the cipher
     */

    /**
     * Creates a message authentication tag for a message with a given key.
     * @param message   The message to generate a MAC for
     * @param key       A secret key to use for MAC'ing the message
     * @return          A valid tag for the message
     */
    public byte[] mac(byte[] message, Key key) {
        // TODO
        return null;
    }

    /**
     * Authenticates a message/tag pair with a key.  Returns true if the pair
     * is authentic, else false.
     * @param message   message to authenticate
     * @param tag       a MAC tag to authenticate with the message
     * @param key       secret key to authenticate the tag with
     */
    public boolean verify(byte[] message, byte[] tag, Key key) {
        // TODO
        return false;
    }

}

