package net.bplaced.javacrypto.keyexchange;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 14.01.2019 
* Funktion: elektronischer Schlüsselaustausch mittels ECDH
* Function: digital key exchange using ECDH
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

public class E02_EcdhKeyexchange {

	public static void main(String[] args) throws Exception {
		System.out.println("E02 ECDH Schlüsselaustausch");

		String ecdhCurvenameString = "secp256r1";
		// standard kurvennamen
		// secp256r1 [NIST P-256, X9.62 prime256v1]
		// secp384r1 [NIST P-384]
		// secp521r1 [NIST P-521]
		
		// jeder der beiden benutzer erzeugt ein eigenes schluessel-paar
		// variablen fuer den benutzer a
		KeyPair aKeyPair = generateEcdhKeyPair(ecdhCurvenameString);
		PrivateKey aPrivateKey = aKeyPair.getPrivate(); // der private schluessel von benutzer a
		PublicKey aPublicKey = aKeyPair.getPublic(); // der public schluessel von benutzer a
		byte[] aSharedSecretByte = null;
		// variablen fuer den benutzer b
		KeyPair bKeyPair = generateEcdhKeyPair(ecdhCurvenameString);
		PrivateKey bPrivateKey = bKeyPair.getPrivate(); // der private schluessel von benutzer b
		PublicKey bPublicKey = bKeyPair.getPublic(); // der public schluessel von benutzer b
		byte[] bSharedSecretByte = null;

		// ausgabe der schluessel fuer jeden benutzer
		System.out.println("\n= = = Erzeugung der Schlüssel von Benutzer A = = =");
		System.out.println("Benutzer A PrivateKey (Hex):" + printHexBinary(aPrivateKey.getEncoded()));
		System.out.println("Benutzer A PublicKey (Hex) :" + printHexBinary(aPublicKey.getEncoded()));
		System.out.println("Benutzer A PublicKey       :" + aPublicKey.toString());
		System.out.println("\n= = = Erzeugung der Schlüssel von Benutzer B = = =");
		System.out.println("Benutzer B PrivateKey (Hex):" + printHexBinary(bPrivateKey.getEncoded()));
		System.out.println("Benutzer B PublicKey (Hex) :" + printHexBinary(bPublicKey.getEncoded()));
		System.out.println("Benutzer B PublicKey       :" + bPublicKey.toString());
		
		// nun werden die public keys untereinander getauscht
		// in der realen welt wird der public key zB per mail oder einer webseite
		// verteilt
		// hier werden die beiden public keys "nur" beim jeweils anderen benutzer
		// angezeigt
		System.out.println("\n= = = Schlüssel bei Benutzer A = = =");
		System.out.println("Benutzer A PrivateKey (Hex):" + printHexBinary(aPrivateKey.getEncoded()));
		System.out.println("Benutzer B PublicKey (Hex) :" + printHexBinary(bPublicKey.getEncoded()));
		System.out.println("\n= = = Schlüssel bei Benutzer B = = =");
		System.out.println("Benutzer B PrivateKey (Hex):" + printHexBinary(bPrivateKey.getEncoded()));
		System.out.println("Benutzer A PublicKey (Hex) :" + printHexBinary(aPublicKey.getEncoded()));

		// erzeugung des shared secret keys bei jedem benutzer
		// benutzer a
		aSharedSecretByte = createEcdhSharedSecret(aPrivateKey, bPublicKey);
		// benutzer b
		bSharedSecretByte = createEcdhSharedSecret(bPrivateKey, aPublicKey);
		
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
		System.out.println("= = = Der gemeinsame Schlüssel wird per SHA-256 Hash auf eine Länge von 32 Byte gebracht = = =");
		System.out.println("SharedSecretByte nach SHA-256Hash (Hex) :" + printHexBinary(sharedSecret32Byte));
		System.out.println("Schlüssel-Länge des SharedSecret32Byte  :" + sharedSecret32Byte.length + " Byte/"
				+ (sharedSecret32Byte.length * 8) + " Bit");
		// ab hier folgt zb die verschluesselung einer datei mittels aes mit nutzung des
		// sharedSecret32Byte als key
	}

	public static KeyPair generateEcdhKeyPair(String curvenameString) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "SunEC");
		ECGenParameterSpec ecParameterSpec = new ECGenParameterSpec(curvenameString); 
		keyPairGenerator.initialize(ecParameterSpec);
		return keyPairGenerator.genKeyPair();
	}
	
	public static byte[] createEcdhSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
		keyAgree.init(privateKey);
		keyAgree.doPhase(publicKey, true);
		return keyAgree.generateSecret();
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
