package org.net;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class CryproRSA {
    public static void main(String[] args) throws  Exception {
        CryptoDigitalImpl crypto = new CryptoDigitalImpl();
        String data = "Je suis Wazabanga";
        PublicKey publicKey = crypto.generetedPublicKey("MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKPAQpz69dvfN2BtaGRnOl48vI1daNS9ez9SB/ldvV8trGvGF9ltDMgsT+ln8EBdvfE8PrDeDeZ58tJkWmXKyAkCAwEAAQ==");
        PrivateKey privateKey=crypto.generetedPriveKey("MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAo8BCnPr12983YG1oZGc6Xjy8jV1o1L17P1IH+V29Xy2sa8YX2W0MyCxP6WfwQF298Tw+sN4N5nny0mRaZcrICQIDAQABAkEAg5vlrgeiDMp11oF4kqHI7q7AGJpHxBxab0T99bUam+Brk4C8VgQJyALO+xprE2AMWEfJLquDxLQgaeRtC0Dg0QIhAO7zGmjd4iqc6C6P2txRyg+GduVESlJB41QLNEN+THe1AiEAr2+AuaggIXZ79Evh4JhMZ0H1mVBTjCD4cL4ObZ7+m4UCICDGLWAm1uebX+lLB+ziNwHMIrCtnjgMG38ijkeXoitlAiBjxe5XqB5d6ZylW2Ki8PrC3uhmwSBC2Z1xwSVDguEaYQIgGmQDUjF9z2F1qSIzMaSA2MfjDfIDZdd5j1ggVJVNCDE=");

        String encodedData = crypto.encrypteDataRSA(data.getBytes(),publicKey);
        System.out.println(encodedData);
        byte[] decryptData = crypto.dencrypteDataRAS(encodedData,privateKey);
        System.out.println(new String(decryptData));

        /* CryptoDigitalImpl crypto = new CryptoDigitalImpl();
        KeyPair keyPair = crypto.generatorKeyRAS();
        PrivateKey privatekey = keyPair.getPrivate();
        System.out.println("Private key");
       // System.out.println(Arrays.toString(privatekey.getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(privatekey.getEncoded()));

        PublicKey publicKey=keyPair.getPublic();
        System.out.println("Public key");
       // System.out.println(Arrays.toString(publicKey.getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
*/
        /*
        String publicKey64 = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKqYj239bQ+n0uy0zODO1yxed/XWhi04zCP2KNNhjXlA68Aar+68S7WJRrN3DcN/wcMO9WUK0ha6oQO4B+h7PYUCAwEAAQ==";
        byte[] decodedPublicKey = Base64.getDecoder().decode(publicKey64.getBytes());
        String document = "Le roi de la forêt";
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodedPublicKey));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedData = cipher.doFinal(document.getBytes());
        System.out.println(Base64.getEncoder().encodeToString(encryptedData));
        System.out.println("==============fin de cryptage des données======");

        System.out.println("==============Decryptage======");
        String privateKey64 ="MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAqpiPbf1tD6fS7LTM4M7XLF539daGLTjMI/Yo02GNeUDrwBqv7rxLtYlGs3cNw3/Bww71ZQrSFrqhA7gH6Hs9hQIDAQABAkBtBgCr30kCt1MyGT3R8f5LibgKcWXgoqq71MY0iOSb9xdMMg7LI+hyYsbY1Vklv/4AARodnGDciv4CoLEhSYehAiEA7HRRjUuBTQKIg89zSeCde/V8RQTKwDZQz3CNTF1C+Z0CIQC4speA940MadHH74j+jRp+q+sSU6fuwxservSBjQAjCQIgTTa6vtIuOhCetbRTqIdRxf3nA77J2rSh9OuDKLG3wj0CIEmB8qBGZeGR4AcFw20j9W6Ct6z0lHqHNizxDqjc2DgZAiBoQo8lhgzuKhTMm8MCWUub02zGlLyWYr5CpodOiiVxkA==";
       String data="CuLZ/ZJGFhtE0o38rIxaNiwA4QXOZphcxJHuDnDbDNWa+w6jUu0lOZMVEZw0A0VGuaHX+RPuX1jOnyMjc9/0Lg==";
        byte[] decodedata = Base64.getDecoder().decode(data.getBytes());
        byte[] decodePrivateKey = Base64.getDecoder().decode(privateKey64);
        KeyFactory keyFactory1 = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory1.generatePrivate(new PKCS8EncodedKeySpec(decodePrivateKey));
        Cipher cipher1 =Cipher.getInstance("RSA");
        cipher1.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedData = cipher1.doFinal(decodedata);
        System.out.println("le message décripté est :");
        System.out.println(new String(decryptedData));

*/

    }
}
