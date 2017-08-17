import sun.misc.BASE64Encoder;

import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

public class Keystore {

//    public static String KEYSTORE_FILENAME = "C:\\Program Files\\Java\\jdk1.8.0_131\\bin\\keystore.jks";
public static String KEYSTORE_FILENAME = "C:\\Program Files\\Java\\jdk1.8.0_131\\jre\\lib\\security\\cacerts";

    private static File keystoreFile;
    private static String keyStoreType;
    private static char[] keyStorePassword;
    private static char[] keyPassword;
    private static String alias;


    public static String getPrivateKey(String alias) throws Exception {
        keystoreFile = new File(KEYSTORE_FILENAME);
        keyStoreType = KeyStore.getDefaultType();
        keyStorePassword = "changeit".toCharArray();
        keyPassword = "changeit".toCharArray();
        KeyStore keystore = KeyStore.getInstance(keyStoreType);
        BASE64Encoder encoder = new BASE64Encoder();
        keystore.load(new FileInputStream(keystoreFile), keyStorePassword);
        Key key = keystore.getKey(alias, keyPassword);
        return encoder.encode(key.getEncoded());
    }

    public static void main(String[] argv) throws Exception {
        FileInputStream is = new FileInputStream(KEYSTORE_FILENAME);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "changeit".toCharArray());

//        String alias = "replserver";
//
//        Key key = keystore.getKey(alias, "password".toCharArray());
//        if (key instanceof PrivateKey) {
//            // Get certificate of public key
//            Certificate cert = keystore.getCertificate(alias);

//            //aliases.stream().forEach(a-> System.out.println(a));
//
//            // Get public key
//            PublicKey publicKey = cert.getPublicKey();
//
//            KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
//
//            System.out.println("Private key algorithm   "+keyPair.getPrivate().getAlgorithm());
//            System.out.println("Private key format   "+keyPair.getPrivate().getFormat());
//            System.out.println("Private key encoded   "+keyPair.getPrivate().getEncoded());
//            System.out.println("Public key   "+keyPair.getPublic().toString());
//
//            getPrivateKey();
//
//        }

        List<String> listOfAliases = new ArrayList<>();

        while (keystore.aliases().hasMoreElements()) {
            listOfAliases.add(keystore.aliases().nextElement());
        }

        listOfAliases.stream().forEach(a -> {
            try {
                System.out.println("Public Key for "+a+" is:  " + keystore.getCertificate(a).getPublicKey().toString());
                //System.out.println("Private Key " + getPrivateKey(a));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

    }
}