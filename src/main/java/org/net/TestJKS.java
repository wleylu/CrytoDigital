package org.net;

import java.security.PrivateKey;
import java.security.PublicKey;

public class TestJKS {
    public static void main(String[] args) throws Exception {
        CryptoDigitalImpl crypto = new CryptoDigitalImpl();
        PublicKey publicKey = crypto.publicKeyFromCertificate("myCertificate.cert");

        System.out.println("=============clé publique===========");
        System.out.println(crypto.encoderToBase64(publicKey.getEncoded()));


        System.out.println("=============clé privé===========");

        PrivateKey privateKey = crypto.privateKeyJKS("leylu.jks","123456","leylu");
        System.out.println(crypto.encoderToBase64(privateKey.getEncoded()));

        String document= "Je suis Wazabanga";
        String eencrypted = crypto.encrypteDataRSA(document.getBytes(),publicKey);
        System.out.println("====================cryper============");
        System.out.println(eencrypted);

        byte[] decrypted = crypto.dencrypteDataRAS(eencrypted,privateKey);
        System.out.println("==============decrypte================");
        System.out.println(new String(decrypted));
    }
}
