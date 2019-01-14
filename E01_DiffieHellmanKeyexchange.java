package net.bplaced.javacrypto.keyexchange;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* Datum/Date (dd.mm.jjjj): 14.01.2019 
* Funktion: elektronischer Schlüsselaustausch mittels Diffie-Hellmann
* Function: digital key exchange using Diffie-Hellmann
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;

public class E01_DiffieHellmanKeyexchange {

	public static void main(String[] args) throws Exception {
		System.out.println("E01 Diffie Hellman Schlüsselaustausch Intern");

		// hinweis: eine sichere schlüssellänge wird erst ab 2048 bit erreicht
		int dhKeyLengthInt = 512; // 512, 1024, 2048, 4096, 8192 bit
		// jeder der beiden benutzer erzeugt ein eigenes schluessel-paar
		// benutzer a

		// unsere variablen fuer den benutzer a
		KeyPair aKeyPair = generateDhKeyPair(dhKeyLengthInt);
		PrivateKey aPrivateKey = aKeyPair.getPrivate(); // der private schluessel von benutzer a
		PublicKey aPublicKey = aKeyPair.getPublic(); // der public schluessel von benutzer a
		byte[] aSharedSecretByte = null;

		// unsere variablen fuer den benutzer b
		KeyPair bKeyPair = generateDhKeyPair(dhKeyLengthInt);
		PrivateKey bPrivateKey = bKeyPair.getPrivate(); // der private schluessel von benutzer a
		PublicKey bPublicKey = bKeyPair.getPublic(); // der public schluessel von benutzer a
		byte[] bSharedSecretByte = null;

		// ausgabe der schluessel fuer jeden benutzer
		System.out.println("\n= = = Erzeugung der Schlüssel von Benutzer A = = =");
		System.out.println("Benutzer A PrivateKey (Hex):" + printHexBinary(aPrivateKey.getEncoded()));
		System.out.println("Benutzer A PublicKey (Hex) :" + printHexBinary(aPublicKey.getEncoded()));
		System.out.println("\n= = = Erzeugung der Schlüssel von Benutzer B = = =");
		System.out.println("Benutzer B PrivateKey (Hex):" + printHexBinary(bPrivateKey.getEncoded()));
		System.out.println("Benutzer B PublicKey (Hex) :" + printHexBinary(bPublicKey.getEncoded()));

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
		aSharedSecretByte = createDhSharedSecret(aPrivateKey, bPublicKey);
		// benutzer b
		bSharedSecretByte = createDhSharedSecret(bPrivateKey, aPublicKey);
		
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

	public static KeyPair generateDhKeyPair(int keylengthInt) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DH");
		keyGenerator.initialize(keylengthInt);
		return keyGenerator.genKeyPair();
	}
	
	public static byte[] createDhSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
		keyAgree.init(privateKey); // initialisierung mit dem private key des benutzers a
		keyAgree.doPhase(publicKey, true); // ergaenzung mit dem public key des benutzers b
		return keyAgree.generateSecret(); // erzeugung des shared keys bei benutzer a
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
