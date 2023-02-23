package testcase;
import security.gm.GMCipher;
import security.gm.GMKeyPairGenerator;
import security.gm.GMPrivateKey;
import security.gm.GMPublicKey;
import security.misc.HomomorphicException;

import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import security.paillier.PaillierSignature;
import security.DGK.DGKOperations;
import security.DGK.DGKKeyPairGenerator;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.DGK.DGKSignature;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalKeyPairGenerator;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamalSignature;
import security.elgamal.ElGamal_Ciphertext;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.List;

public class PaillierTest {
    private static int KEY_SIZE = 1024;
	
	// Key Pairs
	private static KeyPair paillier = null;

	private static PaillierPublicKey pk = null;
	private static PaillierPrivateKey sk = null;

    public static void main(String[] args) throws HomomorphicException{
        System.out.println("==========================  Paillier Test  ====================================");

        // Build Paillier Keys
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		paillier = pa.generateKeyPair();		
		pk = (PaillierPublicKey) paillier.getPublic();
		sk = (PaillierPrivateKey) paillier.getPrivate();


        System.out.println("print paillier keys");
        System.out.println(pk);
        System.out.println(sk);

        System.out.println("======= test encrypt and decrypt ========");
        BigInteger a = PaillierCipher.encrypt(BigInteger.TEN, pk);
        System.out.println(a);

		a = PaillierCipher.decrypt(a, sk);
        System.out.println(a);

        // encrypt(10 + 10) = encrypt(10).add(encrypt(10)), encrypt函数即是从G->H的群同态函数
        System.out.println("======= test addition ========");
		a = PaillierCipher.encrypt(a, pk);        
		a = PaillierCipher.add(a, a, pk);       // 这里的add实际上是相乘后取模
		a = PaillierCipher.decrypt(a, sk);  //20
        System.out.println(a);

		
        System.out.println("======= test subtraction ========");
        a = PaillierCipher.encrypt(a, pk);   
		a = PaillierCipher.subtract(a, PaillierCipher.encrypt(BigInteger.TEN, pk), pk);// 20 - 10
		a = PaillierCipher.decrypt(a, sk);
        System.out.println(a);


		
		System.out.println("======= test multiplication ========");
        a = PaillierCipher.encrypt(a, pk);   
		a = PaillierCipher.multiply(a, BigInteger.TEN, pk); // 10 * 10
        a = PaillierCipher.decrypt(a, sk);
        System.out.println(a);

		
		System.out.println("======= test division ========");
        a = PaillierCipher.encrypt(a, pk);   
		a = PaillierCipher.divide(a, new BigInteger("2"), pk); // 100/2 
        a = PaillierCipher.decrypt(a, sk);
        System.out.println(a);


    }
}
