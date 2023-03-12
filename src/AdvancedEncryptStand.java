public class AdvancedEncryptStand
{
    public static void main(String[] args)
    {
        // String key = "2b7e151628aed2a6abf7158809cf4f3c"; // This is the key used in the NIST-AES examples.
        String key = "0f1571c947d9e8590cb7add6af7f6798"; // This is the key used in our book examples.

        String message = "This is the original message!";
        System.out.println(message);
        String encrypted = AES.encrypt(message, key);
        System.out.println("encrypted: " + encrypted);
        System.out.println("decrypted: " + AES.decrypt(encrypted, key));
        System.out.println();

        // The cipherText below is the text posted on Canvas to be decrypted.
        String cipherText = "4cc88d2df6e8ac02224593a5c7aa940c3fa8b44c79bac4c0323524d16b9640d84b6d7e8e9816008999fbee43837a8444b9b6750b5184591593efd37ef1293ea131da8c4a662abee897bc24f670f8cdab";
        System.out.println("cipherText: " + cipherText);
        System.out.println(AES.decrypt(cipherText, key));
    }
}