package org.net;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoDigitalImpl {

    public CryptoDigitalImpl(){}

    public String encoderToBase64 (byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
    public byte[] decoderToBase64 (String data){
        return Base64.getDecoder().decode(data.getBytes());
    }
    public String encoderToBase64URL (byte[] data){
        return Base64.getUrlEncoder().encodeToString(data);
    }
    public byte[] decoderToBase64URL (String data){
        return Base64.getUrlDecoder().decode(data.getBytes());
    }

    public String encoderToHex (byte[] data){
        return DatatypeConverter.printHexBinary(data);
    }
    public byte[] decoderToHex (String data){
        return DatatypeConverter.parseHexBinary(data);
    }

    public SecretKey generatorKey() throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    public String encrypteDataAES(byte[] data,SecretKey secret) throws  Exception{
        Cipher cipher= Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,secret);
        byte[] encypteData = cipher.doFinal(data);
        String encoderData = Base64.getEncoder().encodeToString(encypteData);

        return encoderData;
    }

    public byte[] dencrypteDataAES(String data,SecretKey secret) throws  Exception{
        byte[] decryptDoc = Base64.getDecoder().decode(data);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,secret);
        byte[] decryptoData = cipher.doFinal(decryptDoc);

        return decryptoData;
    }

    public KeyPair generatorKeyRAS() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
         return keyPairGenerator.generateKeyPair();
    }

    public String encrypteDataRSA(byte[] data,PublicKey publicKey) throws  Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedData = cipher.doFinal(data);
        String encoderData = Base64.getEncoder().encodeToString(encryptedData);

        return encoderData;
    }

    public byte[] dencrypteDataRAS(String data, PrivateKey privateKey) throws  Exception{
        byte[] decryptDoc = Base64.getDecoder().decode(data);
       // KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Cipher cipher =Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decryptedData = cipher.doFinal(decryptDoc);

        return decryptedData;
    }

    public PublicKey generetedPublicKey(String secret) throws Exception{
        byte[] passBase64 = Base64.getDecoder().decode(secret);
        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
        PublicKey publicKey=keyFactory.generatePublic(new X509EncodedKeySpec(passBase64));

        return publicKey;

    }


    public PrivateKey generetedPriveKey(String secret) throws Exception{
        byte[] passBase64 = Base64.getDecoder().decode(secret);
        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
        PrivateKey privateKey=keyFactory.generatePrivate(new PKCS8EncodedKeySpec(passBase64));

        return privateKey;
    }

    public PublicKey publicKeyFromCertificate (String fileName) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
        System.out.println(certificate);
        return  certificate.getPublicKey();
    }

    public PrivateKey privateKeyJKS(String fileName,String jksPassword,String allias) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(fileName);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream, jksPassword.toCharArray());
        Key key = keyStore.getKey(allias,jksPassword.toCharArray());
        PrivateKey privateKey = (PrivateKey) key;

        return privateKey;
    }


}
