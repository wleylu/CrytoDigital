package org.net;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;
import java.util.Base64;


public class Test {
    public static void main(String[] args) {
        CryptoDigitalImpl impl = new CryptoDigitalImpl();
        String document = "C'est un message>>>";

        String codeerDoc64 = impl.encoderToBase64URL(document.getBytes());
        System.out.println(codeerDoc64);
        System.out.println((Arrays.toString(impl.decoderToBase64URL(codeerDoc64))));

        System.out.println(impl.encoderToHex(document.getBytes()));

        System.out.println(impl.decoderToHex(impl.encoderToHex(document.getBytes())));





    }

}
