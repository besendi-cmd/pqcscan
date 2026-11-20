import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

public class Signer {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        Signature sig = Signature.getInstance("SHA256withRSA");
        Cipher legacy = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    }
}
