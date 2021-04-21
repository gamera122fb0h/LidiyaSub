package com.softserveinc.edu.ita;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;


public class TextSignature {
	private KeyPairGenerator keyPairGenerator;
	private KeyPair keyPair;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Signature signature;
	private byte[] realSign;

	/**
	 * This constructor is used when we have pair of public and private keys.
	 * 
	 * @param signAlg
	 *            - the name of the signature algorithm(such as SHA1withDSA,
	 *            SHA1withRSA, MD5withRSA or SHA224withDSA)
	 * 
	 * @param provName
	 *            - the provider
	 */
	public TextSignature(String signAlg, String provName)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		if (signAlg == null) {
			throw new IllegalArgumentException();
		} else {
			if (provName == null) {
				// traverses the list of registered security Providers, starting
				// with the most preferred Provider
				signature = Signature.getInstance(signAlg);
			} else {
				signature = Signature.getInstance(signAlg, provName);
			}
		}
	}

	/**
	 * This constructor is used when we generate pair of public and private key
	 * 
	 * @param keyAlg
	 *            - KeyPairGenerator algorithms - specify when generate an
	 *            instance of KeyPairGenerator( such as DSA, RSA, EC)
	 * 
	 */
	public TextSignature(String keyAlg, int keyLenght, String signAlg,
			String provName) throws NoSuchAlgorithmException,
			NoSuchProviderException {
		if ((keyAlg == null) || (signAlg == null) || (keyLenght <= 0)) {
			throw new IllegalArgumentException();
		} else {
			keyPairGenerator = KeyPairGenerator.getInstance(keyAlg);
			keyPairGenerator.initialize(keyLenght, new SecureRandom());
			System.out.println("Generating key pair ...");
			keyPair = keyPairGenerator.generateKeyPair();
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
			if (provName == null) {
				signature = Signature.getInstance(signAlg);
			} else {
				signature = Signature.getInstance(signAlg, provName);
			}
		}
	}

	public void performSigning(FileInputStream docPath,
			FileOutputStream docWithSignPath) throws InvalidKeyException,
			IOException, SignatureException {
		if ((docPath == null) || (docWithSignPath == null)) {
			// System.out.println("No path for document or document with EDS");
			throw new NullPointerException();
		}
		if (privateKey == null) {
			throw new IllegalArgumentException();
		}
		signature.initSign(privateKey);

		BufferedInputStream bufReader = new BufferedInputStream(docPath);
		byte[] byteDoc = new byte[bufReader.available()];
		bufReader.read(byteDoc);
		System.out.println("Generating signature ...");
		signature.update(byteDoc);
		bufReader.close();

		ObjectOutputStream oos = new ObjectOutputStream(docWithSignPath);
		oos.writeObject(byteDoc);
		realSign = signature.sign();
		oos.writeObject(realSign);
	}

	public boolean performVerification(FileInputStream signingDoc)
			throws IOException, InvalidKeyException, SignatureException,
			ClassNotFoundException {

		if (signingDoc == null) {
			throw new NullPointerException();
		}

		ObjectInputStream oisWithSign = new ObjectInputStream(signingDoc);
		Object objWithSign = oisWithSign.readObject();
		byte[] document = (byte[]) objWithSign;// received document

		FileOutputStream fos = new FileOutputStream("receivedDoc");
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(document);

		objWithSign = oisWithSign.readObject();
		byte[] sign = (byte[]) objWithSign;
		oos.close();

		// Verifying
		System.out.println("Verifying signature ...");
		signature.initVerify(publicKey);
		signature.update(document);

		return signature.verify(sign);

	}

	public byte[] getRealSign() {
		return realSign;
	}

	public void savePrivateKey(FileOutputStream fos) throws IOException {
		if (fos == null && privateKey == null) {
			throw new NullPointerException();
		} else {
			ObjectOutputStream objStream = new ObjectOutputStream(fos);
			objStream.writeObject(privateKey);
			objStream.close();
		}
	}

	public void savePublicKey(FileOutputStream fos) throws IOException {
		if (fos == null && publicKey == null) {
			throw new NullPointerException();
		} else {
			ObjectOutputStream objStream = new ObjectOutputStream(fos);
			objStream.writeObject(publicKey);
			objStream.close();
		}
	}

	public PrivateKey readPrivateKey(FileInputStream fis) throws IOException,
			ClassNotFoundException {
		if (fis == null) {
			throw new NullPointerException();
		} else {
			ObjectInputStream objInputStrm = new ObjectInputStream(fis);
			Object obj = objInputStrm.readObject();
			if (obj instanceof PrivateKey) {
				PrivateKey prKey = (PrivateKey) obj;
				return prKey;
			} else {
				throw new ClassCastException();
			}
		}
	}

	public PublicKey readPublicKey(FileInputStream fis) throws IOException,
			ClassNotFoundException {
		if (fis == null) {
			throw new NullPointerException();
		} else {
			ObjectInputStream objInputStrm = new ObjectInputStream(fis);
			Object obj = objInputStrm.readObject();
			if (obj instanceof PublicKey) {
				PublicKey pubKey = (PublicKey) obj;
				return pubKey;
			} else {
				throw new ClassCastException();
			}
		}
	}

	public KeyPair getPair(FileInputStream inStrm, String alias,
			char[] passKeyStore, char[] passCertificate)
			throws NoSuchAlgorithmException, CertificateException, IOException,
			KeyStoreException, UnrecoverableKeyException {
		// The proprietary keystore implementation provided by the SUN provider.
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(inStrm, passKeyStore);
		Key key = keyStore.getKey(alias, passCertificate);
		if (key instanceof PrivateKey) {
			// get certificate of public key
			Certificate cert = keyStore.getCertificate(alias);
			PublicKey pubKey = cert.getPublicKey();
			return new KeyPair(pubKey, (PrivateKey) key);
		}
		return null;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

}
