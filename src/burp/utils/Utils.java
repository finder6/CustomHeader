package burp.utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.GetMethod;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Random;

public class Utils {
    private static MessageDigest md;
    private static Random rand = new Random();

    public static int GetRandomNumber(int min, int max) {
        return rand.nextInt(max - min + 1) + min;
    }

    public static byte[] HTTPGet(String uri) {
        HttpClient client = new HttpClient();
        byte[] resp = null;
        client.getHttpConnectionManager().getParams().setConnectionTimeout(3000);
        try {
            GetMethod request = new GetMethod(uri);
            client.executeMethod(request);
            resp = request.getResponseBody();
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            return resp;
        }
    }

    public static String encode(byte[] data, OutFormat outFormat) {
        switch (outFormat) {
            case HEX:
                return hex(data);
            case Base64:
                return base64(data);
        }
        return null;
    }

    public static byte[] byteMerger(byte[] bt1, byte[] bt2) {
        byte[] bt3 = new byte[bt1.length + bt2.length];
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);
        return bt3;
    }

    public static byte[] MD5(byte[] src) {
        if (md == null) {
            try {
                md = MessageDigest.getInstance("md5");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("MD5 not found!");
            }
        }
        byte[] secretBytes = null;
        secretBytes = md.digest(src);
        return secretBytes;
    }

    public static byte[] StringKeyToByteKey(String value, KeyFormat format) {
        try {
            switch (format) {
                case HEX:
                    return hex(value);
                case Base64:
                    return base64(value);
                case UTF8String:
                    return value.getBytes("UTF-8");
            }
        } catch (UnsupportedEncodingException ex) {
            System.out.println(ex);
        }
        return null;
    }

    public static String base64(byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    public static byte[] base64(String str) {
        return Base64.decodeBase64(str);
    }

    public static String hex(byte[] bytes) {
        return Hex.encodeHexString(bytes);
    }

    public static byte[] hex(String str) {
        try {
            return Hex.decodeHex(str.toCharArray());
        } catch (DecoderException e) {
            throw new IllegalStateException(e);
        }
    }

    public static BigInteger[] getBase64PublicKeyME(String base64Str) throws Exception {
        BigInteger[] result = new BigInteger[2];
        byte[] decoded = Base64.decodeBase64(base64Str);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        result[0] = pubKey.getModulus();
        result[1] = pubKey.getPublicExponent();
        return result;
    }


    public static String[] GetOutFormats() {
        ArrayList<String> strs = new ArrayList<String>();
        OutFormat[] items = OutFormat.values();
        for (OutFormat item : items) {
            strs.add(item.name());
        }
        return strs.toArray(new String[strs.size()]);
    }

    public static byte[] ZeroPadding(byte[] data, int blockSize) {
        int length = data.length;
        if (length % blockSize != 0) {
            length = length + (blockSize - (length % blockSize));
        }
        byte[] dataBytes = new byte[length];
        System.arraycopy(data, 0, dataBytes, 0, data.length);
        return dataBytes;
    }

    public static String[] GetPublicKeyFormats() {
        ArrayList<String> strs = new ArrayList<String>();
        PublicKeyFormat[] items = PublicKeyFormat.values();
        for (PublicKeyFormat item : items) {
            strs.add(item.name());
        }
        return strs.toArray(new String[strs.size()]);
    }

    public static String[] GetKeyFormats() {
        ArrayList<String> strs = new ArrayList<String>();
        KeyFormat[] items = KeyFormat.values();
        for (KeyFormat item : items) {
            strs.add(item.name());
        }
        return strs.toArray(new String[strs.size()]);
    }
}
