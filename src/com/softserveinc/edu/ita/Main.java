package com.softserveinc.edu.ita;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;

public class Main {
	public static void main(String[] args) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, SignatureException,
			FileNotFoundException, IOException, ClassNotFoundException {
		// Provider[] mas = Security.getProviders();
		// for (int i = 0; i < mas.length; i++) {
		// System.out.println(mas[i]);
		// }
		TextSignature sign = new TextSignature("DSA", 1024, "SHA1withDSA",
				"SUN");

		// Signing DS documents
		sign.performSigning(new FileInputStream("InputDocument.txt"),
				new FileOutputStream("OutputDocumentWithSign.txt"));
		// sign.savePublicKey(new FileOutputStream("fileWithPubKey.txt"));
		// sign.readPublicKey(new FileInputStream("fileWithPubKey.txt"));

		// implementation of verification DS
		boolean resultVerify = sign.performVerification(new FileInputStream(
				"OutputDocumentWithSign.txt"));
		if (resultVerify) {
			System.out.println("Document is valid");
		} else {
			System.out.print("Document was corrupted");
		}

	}
}
