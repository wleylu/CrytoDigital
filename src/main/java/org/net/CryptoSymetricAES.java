package org.net;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CryptoSymetricAES {


    public static void main(String[] args) throws Exception {
       CryptoDigitalImpl cripto = new CryptoDigitalImpl();
        String document ="Miss Mayssane la plus belle " ;
        SecretKey key = cripto.generatorKey();
        String encrypt = cripto.encrypteDataAES(document.getBytes(),key);
        System.out.println(encrypt);


        byte[] decrypt = cripto.dencrypteDataAES(encrypt,key);
        System.out.println(new String(decrypt));

    }
}
