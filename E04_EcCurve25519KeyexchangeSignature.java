package net.bplaced.javacrypto.keyexchange;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 18.01.2019 
* Funktion: elektronischer Schlüsselaustausch und Signatur mittels ECDH
* Function: digital key exchange and signature using ECDH
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

// benötigt: curve25519-java-0.5.0.jar
// source: https://github.com/signalapp/curve25519-java
// jar: http://central.maven.org/maven2/org/whispersystems/curve25519-java/0.5.0/curve25519-java-0.5.0.jar

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;


public class E04_EcCurve25519KeyexchangeSignature {

	public static void main(String[] args) throws Exception {
		System.out.println("E04 EC Kurve 25519 Schlüsselaustausch mit Signatur");

		// jeder der beiden benutzer erzeugt ein eigenes schluessel-paar
		// variablen fuer den benutzer a
		Curve25519KeyPair aKeyPair = generateEcCurve25519KeyPair();
		byte[] aPrivateKeyByte = aKeyPair.getPrivateKey(); // der private schluessel von benutzer a
		byte[] aPublicKeyByte = aKeyPair.getPublicKey(); // der public schluessel von benutzer a
		byte[] aSharedSecretByte = null;
		// variablen fuer den benutzer b
		Curve25519KeyPair bKeyPair = generateEcCurve25519KeyPair();
		byte[] bPrivateKeyByte = bKeyPair.getPrivateKey(); // der private schluessel von benutzer b
		byte[] bPublicKeyByte = bKeyPair.getPublicKey(); // der public schluessel von benutzer b
		byte[] bSharedSecretByte = null;

		// ausgabe der schluessel fuer jeden benutzer
		System.out.println("\n= = = Erzeugung der Schlüssel von Benutzer A = = =");
		System.out.println("Benutzer A PrivateKey (Hex):" + printHexBinary(aPrivateKeyByte));
		System.out.println("Benutzer A PublicKey (Hex) :" + printHexBinary(aPublicKeyByte));
		System.out.println("\n= = = Erzeugung der Schlüssel von Benutzer B = = =");
		System.out.println("Benutzer B PrivateKey (Hex):" + printHexBinary(bPrivateKeyByte));
		System.out.println("Benutzer B PublicKey (Hex) :" + printHexBinary(bPublicKeyByte));

		// nun werden die public keys untereinander getauscht
		// in der realen welt wird der public key zB per mail oder einer webseite
		// verteilt
		// hier werden die beiden public keys "nur" beim jeweils anderen benutzer
		// angezeigt
		System.out.println("\n= = = Schlüssel bei Benutzer A = = =");
		System.out.println("Benutzer A PrivateKey (Hex):" + printHexBinary(aPrivateKeyByte));
		System.out.println("Benutzer B PublicKey (Hex) :" + printHexBinary(bPublicKeyByte));
		System.out.println("\n= = = Schlüssel bei Benutzer B = = =");
		System.out.println("Benutzer B PrivateKey (Hex):" + printHexBinary(bPrivateKeyByte));
		System.out.println("Benutzer A PublicKey (Hex) :" + printHexBinary(aPublicKeyByte));

		// erzeugung des shared secret keys bei jedem benutzer
		// benutzer a
		aSharedSecretByte = createEcCurve25519SharedSecret(aPrivateKeyByte, bPublicKeyByte);
		// benutzer b
		bSharedSecretByte = createEcCurve25519SharedSecret(bPrivateKeyByte, aPublicKeyByte);

		// ausgabe der shared keys fuer jeden benutzer
		System.out.println("\n= = = Gemeinsame Schlüssel (SharedSecred) bei den Benutzern = = =");
		System.out.println("Benutzer A SharedSecret (Hex):" + printHexBinary(aSharedSecretByte));
		System.out.println("Benutzer B SharedSecret (Hex):" + printHexBinary(bSharedSecretByte));

		// die laenge des schluessels duerfte zu gross fuer viele aes-verfahren sein,
		// daher kuerzen wir den schluessel mittels eines hashes
		System.out.println("\nSchlüssel-Länge des SharedSecretByte    :" + aSharedSecretByte.length + " Byte/"
				+ (aSharedSecretByte.length * 8) + " Bit");
		// hashing der ausgabe um einen 32 byte = 256 bit schluessel zu erhalten
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] sharedSecret32Byte = digest.digest(aSharedSecretByte);
		System.out.println(
				"= = = Der gemeinsame Schlüssel wird per SHA-256 Hash auf eine Länge von 32 Byte gebracht = = =");
		System.out.println("SharedSecretByte nach SHA-256Hash (Hex) :" + printHexBinary(sharedSecret32Byte));
		System.out.println("Schlüssel-Länge des SharedSecret32Byte  :" + sharedSecret32Byte.length + " Byte/"
				+ (sharedSecret32Byte.length * 8) + " Bit");

		// erzeugung der digitalen signatur
		System.out.println("\nDie Nachricht wird mit dem privateKey signiert");
		byte[] messageByte = "Das ist die zu signierende Nachricht".getBytes("utf-8");
		byte[] signatureByte = signCurve25519PrivateKey(aPrivateKeyByte, messageByte);
		System.out.println(
				"signatureByte Länge:" + signatureByte.length + " Data:\n" + byteArrayPrint(signatureByte, 33));

		// verifizierung der digitalen signatur
		System.out.println("\nDie Nachricht wird mit dem publicKey verifiziert");
		Boolean signatureIsCorrectBoolean = verifyCurve25519PublicKey(aPublicKeyByte, messageByte, signatureByte);
		System.out.println(
				"Überprüfung der Signatur mit dem publicKey: die Signatur ist korrekt:" + signatureIsCorrectBoolean);
	}

	public static Curve25519KeyPair generateEcCurve25519KeyPair()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST);
		return Curve25519.getInstance(Curve25519.BEST).generateKeyPair();
	}

	public static byte[] createEcCurve25519SharedSecret(byte[] aPrivateKeyByte, byte[] bPublicKeyByte)
			throws NoSuchAlgorithmException, InvalidKeyException {
		Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST);
		return cipher.calculateAgreement(bPublicKeyByte, aPrivateKeyByte);
	}

	public static byte[] signCurve25519PrivateKey(byte[] privateKeyByte, byte[] messageByte)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST);
		return cipher.calculateSignature(privateKeyByte, messageByte);
	}

	public static Boolean verifyCurve25519PublicKey(byte[] publicKeyByte, byte[] messageByte, byte[] signatureByte)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST);
		return cipher.verifySignature(publicKeyByte, messageByte, signatureByte);

	}

	public static String byteArrayPrint(byte[] byteData, int numberPerRow) {
		String returnString = "";
		String rawString = printHexBinary(byteData);
		int rawLength = rawString.length();
		int i = 0;
		int j = 1;
		int z = 0;
		for (i = 0; i < rawLength; i++) {
			z++;
			returnString = returnString + rawString.charAt(i);
			if (j == 2) {
				returnString = returnString + " ";
				j = 0;
			}
			j++;
			if (z == (numberPerRow * 2)) {
				returnString = returnString + "\n";
				z = 0;
			}
		}
		return returnString;
	}

	public static String printHexBinary(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}
