package com.example.myapplication;

import static java.text.DateFormat.Field.TIME_ZONE;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import javax.crypto.Cipher;

public class MainActivity extends AppCompatActivity {

    int count = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {

            String publickKeyString = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCW9TUwkBus7FQ5oPgWqh9kVsaVgrL5oYV6tqFfs2j698PCStkQarhp3QoF58VZHO5d6COgipxQWRuAlF4w4ICziVJjXZSnrrxgis2ngij5afjgtkSw3pPIoklXjiXojCpRv57JP8/iH6yFdZMJRS19YrmHCMPEUSLhjtjVDa9/FQIDAQAB";
            String privateKeyString = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJTm5mIBQ0wBirO6xkEvQAtNeoDPMBLQ4cfLABUC040q3+TJXZ2cIr2q1bqOg+uh9nBbfbluPu0O3m6NYGlVSeCNXX1Pezmx9PpLmTkD8i8JQgfiau+5UK3WX2tSqYI5tsUSv3DSqpXTa6LpeUbeNY7rqUcIdRsM+7lMSBqX643ZAgMBAAECgYAYQZT+Gh6QXx/tL1vkeoIAVVrDaPz307c0CMm2ooM71+QpLPRnHGw8YXv3rAepdvTiUMUmU+NEUsvBTp6KCi7CeiiFAxcZk1XsjdY+/46M28ZIYG+8PmS6HmbPfnLpwaZGqPkwG31sey26dRaXBUHKFLaLlXF7bQykC+QJBW00AQJBAMPf4bospC3Sh/JDENgOeLj1/olj9eIMr7X52GUDm4KhuOSYOi+wACfSxTKJMhnmrrUsMCqBxsBjZBDIIsay9+ECQQDCm9dZKjdEpm4J2dRkuwimWrVClIghGQKPQON3taBlK0rtadlj1FCYphAx4IpEh0pU+ZTOGUqNDI6T1iy6VvT5AkAq7XcQEVaOAFTxAEfBwjIs/ySgwbqSpwsfS7lkMg0z7POTjdU6vEzcbXHwaGcFjCv/4sZPmo+PfHjiwKn2eCShAkEAwEokOuJPwfGBARLPnsh//3/ZYnRJHgsMUGgZWouIdO6WFohkWRPMn0hW8DGh7ZyQge4qborm8v/ZUZJql6ScYQJAZZZbkzvgMfgEWrO2V59rRmNr35dIgiPw5hfMCviRG+uEaDRXPFBQsou+I+ta7EOSezPKx+c4UMtM24y0nBJ0RA==";

//            //Gen 1 cặp publicKey và privateKey để test
//            String stringToGenKey2 = "khfkfsdkfhskfhiuwrhwefdskfsdkfjhdkfjhdkfhieufhwf";
//            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//            byte[] seed6 = stringToGenKey2.getBytes();
//            SecureRandom secureRandom = new SecureRandom(seed6);
//            generator.initialize(1024, secureRandom);
//            KeyPair pair = generator.generateKeyPair();
//            PublicKey publicKey2 = pair.getPublic();
//            PrivateKey privateKey1 = pair.getPrivate();
//            String publickKeyString2 = convertPublicKeyToString(publicKey2);
//            String privateKeyString2 = convertPrivateKeyToString(privateKey1);

            String stringToGenKey = "khfkfsdkfhskfhiuwrhwefdskfsdkfjhdkfjhdkfhieufhwf";
            // Generate key pair
            Pair<PrivateKey, PublicKey> keyPair = generateKeyPair(stringToGenKey);

            // Retrieve the private key and convert it to a string
            PrivateKey privateKey = keyPair.first;
            PublicKey publicKey1 = keyPair.second;
            String t = convertPublicKeyToString(publicKey1);

            // Retrieve the public key and convert it to a string
            PublicKey publicKey = getPublicKeyFromString(publickKeyString);

            String encryptedText = encrypt(createOTPByTime(System.currentTimeMillis() / 1000), publicKey1);
            Log.d("Encrypted Text: ", encryptedText);
            System.out.println("--------");

            String decryptedText = decrypt(encryptedText, privateKey);
            Log.d("Decrypted Text: ", decryptedText);

        }catch (Exception e) {

        }


//        new Thread(new Runnable() {
//            @Override
//            public void run() {
//                for (int i = 0; i <= 200; i++) {
//                    createOTPByTime(System.currentTimeMillis() / 1000);
//                    try {
//                        Thread.sleep(1000);
//                    } catch (InterruptedException e) {
//                        e.printStackTrace();
//                    }
//                }
//            }
//        }).start();
    }


    public String convertPublicKeyToString(PublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getEncoded();
        String publicKeyString = Base64.encodeToString(publicKeyBytes, Base64.DEFAULT);
        return publicKeyString;
    }

    public String convertPrivateKeyToString(PrivateKey privateKey) {
        byte[] privateKeyBytes = privateKey.getEncoded();
        String privateKeyString = Base64.encodeToString(privateKeyBytes, Base64.DEFAULT);
        return privateKeyString;
    }


    public  String createOTPByTime(long time) {

        DateFormat df1 = new SimpleDateFormat("yyyyMMddHH");
        df1.setTimeZone(TimeZone.getTimeZone("Asia/Ho_Chi_Minh"));
        String utcTime1 = df1.format(new Date());
        String timeStamp = 60 + utcTime1 + "47a4b25cf1974785" + "84948768316";
        timeStamp = stringToHex(timeStamp);
        long T0 = 0;
        //30s gen 1 otp
        long X = 60;


        String steps = "0";
        try {
            System.out.println(
                    "+---------------+-----------------------+" +
                            "------------------+--------+--------+"
            );
            System.out.println(
                    "|  Time(sec)      " +
                            "| Value of T(Hex)  |  TOTP  | Mode   |"
            );
            System.out.println(
                    "+---------------+-----------------------+" +
                            "------------------+--------+--------+"
            );
            long T = (time - T0) / X;
            steps = Long.toHexString(T).toUpperCase(Locale.getDefault());
            while (steps.length() < 16) {
                steps = "0" + steps;
            }
            String fmtTime = String.format("%1$-11s", time);

            count ++;
            System.out.print(
                    ("|  " + fmtTime + "  |  " +
                            "  | " + steps + " | " + count + " | " + T + "--")
            );

            System.out.println(
                    TOTP.generateTOTP256(timeStamp, steps, "5") + "| SHA256 |"
            );
            String otp = TOTP.generateTOTP256(timeStamp, steps, "5");

            long time1 = time / X;
            long time2 = time - time1 * X;
            Log.i("XXX", "OTP: " + otp  + "- time con lai:" + (X - time2));

            return otp;
        } catch (Exception e) {
            System.out.println("Error: " + e);
            return  "";
        }
    }
    public String stringToHex(String string) {
        byte[] bytes = string.getBytes(StandardCharsets.UTF_8);

        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }

        return hexString.toString();

    }





    public  Pair<PrivateKey, PublicKey> generateKeyPair(String keyName) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                keyName,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4))
                .build();
        keyPairGenerator.initialize(keyGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return new Pair<>(keyPair.getPrivate(), keyPair.getPublic());
    }

    public static String encrypt(String text, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(text.getBytes());
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
    }

    public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = Base64.decode(encryptedText, Base64.DEFAULT);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static RSAPrivateKey getPrivateKeyFromString(String privateKeyString) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKeyString, Base64.DEFAULT));
        return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }

    public static RSAPublicKey getPublicKeyFromString(String publicKeyString) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(publicKeyString, Base64.DEFAULT));
        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    }

//      Mã hoá chiều đi
//    Tạo và xử lý Key để mã hoá OTP giữa app và be
//    B1: Be sinh 1 cặp publicKey và privateKey
//    B2: Giữ lại privateKey và convert publicKey thành string theo hàm convertPublicKeyToString và gửi cho app lưu lại
//    B3: App sẽ nhận được publicKey sau đó khi gen OTP từ hàm createOTPByTime xong sẽ mã hoá otp theo publicKey(phải chuyển từ publicKeyString -> PublicKey theo hàm getPublicKeyFromString) đã lưu theo hàm encrypt -> sau đó gửi chuỗi đã mã hoá cho Be
//    B4: Khi Be nhận được chuỗi mã hoá từ app -> giải mã chuỗi đó theo privatekey đã sinh ở bước 1, -> giải mã trả ra otp , đồng thời cũng gen otp từ hàm createOTPByTime sau đó so sánh otp gen ra và otp giải mã từ app gửi

}