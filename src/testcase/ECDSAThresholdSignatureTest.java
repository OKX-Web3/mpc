package testcase;


import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.ED25519core;
import com.okx.ecdsa.Curve25519core;
import com.okx.ecdsa.Point;
import com.okx.ecdsa.utils.Base58;
import com.okx.ecdsa.utils.HEX;
import com.okx.ecdsa.utils.HashUtil;

import security.misc.HomomorphicException;

import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.math.BigInteger;
import java.security.KeyPair;


public class ECDSAThresholdSignatureTest {
    public static void main(String[] args) throws HomomorphicException{

        System.out.println("==========================  ECDSA Threshold Signature (3,3)  ====================================");
        // https://eprint.iacr.org/2020/540.pdf
        // https://dl.acm.org/doi/10.1145/3243734.3243859

        ecdsaThresholdSignature33();

        System.out.println("==========================  ECDSA Threshold Signature (2,3)  ====================================");

        ecdsaThresholdSignature23();


    }

    private static void ecdsaThresholdSignature33() throws HomomorphicException{
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
        ECDSAcore acore = new ECDSAcore();
        PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();

        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
        BigInteger ZERO = new BigInteger("0", 16);
        BigInteger ONE = new BigInteger("1", 16);
        BigInteger TWO = new BigInteger("2", 16);
        BigInteger THREE = new BigInteger("3", 16);

        //================= 1. generate private key ===================

        BigInteger u1 = new BigInteger("333", 16);  // P1 kept u1 as a secret
        BigInteger u2 = new BigInteger("666", 16);  // P2 kept u2 as a secret
        BigInteger u3 = new BigInteger("999", 16);  // P3 kept u3 as a secret
        System.out.println("聚合私钥 x: " + u1.add(u2).add(u3));

        Point y1 = acore.fastMultiply(u1);  // P1 reveal y1
        Point y2 = acore.fastMultiply(u2);  // P2 reveal y2
        Point y3 = acore.fastMultiply(u3);  // P3 reveal y3
        Point y = acore.add(y1, acore.add(y2, y3)); // y is aggregate pubkey

        // f1(x) = a11 + a12 * x + a13 * x^2, a11 = u1
        // P1 generate a12, a13
        BigInteger a12 = new BigInteger("218", 16);
        BigInteger a13 = new BigInteger("526", 16);
        // P1 calculate f1(1), f1(2), f1(3)，  f1(2) -> P2， f1(3) -> P3
        BigInteger f11 = u1.add(a12).add(a13);      // P1 
        BigInteger f12 = u1.add(a12.multiply(TWO)).add(a13.multiply(TWO.multiply(TWO)));    // -> P2
        BigInteger f13 = u1.add(a12.multiply(THREE).add(a13.multiply(THREE.multiply(THREE))));  // -> P3

        // P2 generate a22, a23
        BigInteger a22 = new BigInteger("269", 16);
        BigInteger a23 = new BigInteger("317", 16);
        BigInteger f21 = u2.add(a22).add(a23);      // -> P1
        BigInteger f22 = u2.add(a22.multiply(TWO)).add(a23.multiply(TWO.multiply(TWO)));    // P2 
        BigInteger f23 = u2.add(a22.multiply(THREE).add(a23.multiply(THREE.multiply(THREE))));  // -> P3

        BigInteger a32 = new BigInteger("581", 16);
        BigInteger a33 = new BigInteger("729", 16);
        BigInteger f31 = u3.add(a32).add(a33);      
        BigInteger f32 = u3.add(a32.multiply(TWO)).add(a33.multiply(TWO.multiply(TWO)));    
        BigInteger f33 = u3.add(a32.multiply(THREE).add(a33.multiply(THREE.multiply(THREE))));  

        // xi = f1i + f2i + f3i
        BigInteger x1 = f11.add(f21).add(f31);      // (1,x1),(2,x2),(3,x3)
        BigInteger x2 = f12.add(f22).add(f32);
        BigInteger x3 = f13.add(f23).add(f33);
        System.out.println(x1);
        System.out.println(x2);
        System.out.println(x3);


        //  w1 + w2 + w3 = x， wi = lamdai * xi
        // f(x) = f1(x) + f2(x) + f3(x),  f(1) = x1, f(2) = x2, f(3) = x3
        // f(x) = a1 + a2 * x + a3 * x^2
        // f(x) = x1*I1(x) + x2*I2(x) + x3*I3(x)
        // f(0) = x1*I1(0) + x2*I2(0) + x3*I3(0)
        // f(0) = a1 = x
        // lamdai = Ii(0)
        BigInteger lamda1 = (ZERO.subtract(TWO)).multiply(ZERO.subtract(THREE)).divide(ONE.subtract(TWO)).divide(ONE.subtract(THREE));
        BigInteger w1 = lamda1.multiply(x1).mod(n);     // P1 keeps w1 as a secret

        BigInteger lamda2 = (ZERO.subtract(ONE)).multiply(ZERO.subtract(THREE)).divide(TWO.subtract(ONE)).divide(TWO.subtract(THREE));
        BigInteger w2 = lamda2.multiply(x2).mod(n);     // P2 keeps w2 as a secret

        BigInteger lamda3 = (ZERO.subtract(ONE)).multiply(ZERO.subtract(TWO)).divide(THREE.subtract(ONE)).divide(THREE.subtract(TWO));
        BigInteger w3 = lamda3.multiply(x3).mod(n);     // P3 keeps w3 as a secret

        System.out.println("w1+w2+w3 : " + w1.add(w2).add(w3).mod(n));

        // 1.8 P1， P2，P3 generate Paillier key pair
		KeyPair paillier1 = pa.generateKeyPair();		
		PaillierPublicKey pk1 = (PaillierPublicKey) paillier1.getPublic();
		PaillierPrivateKey sk1 = (PaillierPrivateKey) paillier1.getPrivate();

		KeyPair paillier2 = pa.generateKeyPair();		
		PaillierPublicKey pk2 = (PaillierPublicKey) paillier2.getPublic();
		PaillierPrivateKey sk2 = (PaillierPrivateKey) paillier2.getPrivate();

		KeyPair paillier3 = pa.generateKeyPair();		
		PaillierPublicKey pk3 = (PaillierPublicKey) paillier3.getPublic();
		PaillierPrivateKey sk3 = (PaillierPrivateKey) paillier3.getPrivate();

        //================= 2.sign ===================

        // P1,P2,P3 generate ki,  k = k1 + k2 + k3
        BigInteger k1 = new BigInteger("716", 16);  // P1 kept k1 as a secret
        BigInteger k2 = new BigInteger("635", 16);  // P2 kept k2 as a secret
        BigInteger k3 = new BigInteger("862", 16);  // P3 kept k3 as a secret

        // P1,P2,P3 generate gammai, 且 gamma = gamma1 + gamma2 + gamma3
        BigInteger gamma1 = new BigInteger("534", 16);  // P1 kept k1 as a secret
        BigInteger gamma2 = new BigInteger("678", 16);  // P2 kept k2 as a secret
        BigInteger gamma3 = new BigInteger("921", 16);  // P3 kept k3 as a secret   
        
        // MtA  delta = k * gamma
        // k1 * gamma2 = alpha12 + beta12
        BigInteger en_k1 = PaillierCipher.encrypt(k1, pk1);
        // en_alpha12 = homo_add(en_m12, homo_mul(en_k1, gamma1, pk1))
        BigInteger m12 = new BigInteger("586", 16);
        BigInteger en_alpha12 = MtA(en_k1, gamma2, m12, pk1);
        BigInteger alpha12 = PaillierCipher.decrypt(en_alpha12, sk1).mod(n);    // P1 keeps alpha12 as a secret
        BigInteger beta12 = new BigInteger("0").subtract(m12).mod(n);       // P2 keeps beta12 as a secret

        BigInteger m13 = new BigInteger("896", 16);
        BigInteger en_alpha13 = MtA(en_k1, gamma3, m13, pk1);
        BigInteger alpha13 = PaillierCipher.decrypt(en_alpha13, sk1).mod(n);    // P1 keeps alpha13 as a secret
        BigInteger beta13 = new BigInteger("0").subtract(m13).mod(n);       // P3 keeps beta13 as a secret

        BigInteger en_k2 = PaillierCipher.encrypt(k2, pk2);
        BigInteger m21 = new BigInteger("775", 16);
        BigInteger en_alpha21 = MtA(en_k2, gamma1, m21, pk2);
        BigInteger alpha21 = PaillierCipher.decrypt(en_alpha21, sk2).mod(n);    // P2 keeps alpha21 as a secret
        BigInteger beta21 = new BigInteger("0").subtract(m21).mod(n);       // P1 keeps beta21 as a secret

        BigInteger m23 = new BigInteger("352", 16);
        BigInteger en_alpha23 = MtA(en_k2, gamma3, m23, pk2);
        BigInteger alpha23 = PaillierCipher.decrypt(en_alpha23, sk2).mod(n);    // P2 keeps alpha23 as a secret
        BigInteger beta23 = new BigInteger("0").subtract(m23).mod(n);       // P3 keeps beta23 as a secret

        BigInteger en_k3 = PaillierCipher.encrypt(k3, pk3);
        BigInteger m31 = new BigInteger("178", 16);
        BigInteger en_alpha31 = MtA(en_k3, gamma1, m31, pk3);
        BigInteger alpha31 = PaillierCipher.decrypt(en_alpha31, sk3).mod(n);    // P3 keeps alpha31 as a secret
        BigInteger beta31 = new BigInteger("0").subtract(m31).mod(n);       // P1 keeps beta31 as a secret

        BigInteger m32 = new BigInteger("219", 16);
        BigInteger en_alpha32 = MtA(en_k3, gamma2, m32, pk3);
        BigInteger alpha32 = PaillierCipher.decrypt(en_alpha32, sk3).mod(n);    // P3 keeps alpha32 as a secret
        BigInteger beta32 = new BigInteger("0").subtract(m32).mod(n);       // P2 keeps beta32 as a secret
 
        BigInteger delta_share1 = k1.multiply(gamma1).add(alpha12).add(beta21).add(alpha13).add(beta31).mod(n);      // P1 reveal delta_share1
        BigInteger delta_share2 = k2.multiply(gamma2).add(alpha21).add(beta12).add(alpha23).add(beta32).mod(n);      // P2 reveal delta_share2
        BigInteger delta_share3 = k3.multiply(gamma3).add(alpha31).add(beta13).add(alpha32).add(beta23).mod(n);      // P3 reveal delta_share3

        BigInteger delta = delta_share1.add(delta_share2).add(delta_share3).mod(n);

        // R = k^(-1) * g = gamma * g / (k * gamma) = gamma * g / delta
        // gammai * g
        Point Gamma1 = acore.fastMultiply(gamma1);  // P1 reveal Gamma1
        Point Gamma2 = acore.fastMultiply(gamma2);  // P1 reveal Gamma2
        Point Gamma3 = acore.fastMultiply(gamma3);  // P1 reveal Gamma3
        // Gamma = Gamma1 + Gamma2 + Gamma3
        Point Gamma = acore.add(Gamma1, acore.add(Gamma2, Gamma3));
        //2.4.3 R = k^(-1) * g = delta^(-1) * gamma * g = delta^(-1) * Gamma
        Point R = acore.fastMultiplyWithPoint(delta.modInverse(n), Gamma);
        BigInteger r = R.getX();
        System.out.println("R : " + R);
        System.out.println("r : " + r);

        // MtA，sigma = k * w
        // k1 * w2 = u12 + v12
        BigInteger n12 = new BigInteger("11f", 16);
        BigInteger en_u12 = MtA(en_k1, w2, n12, pk1);
        BigInteger u12 = PaillierCipher.decrypt(en_u12, sk1).mod(n);    // P1 keeps u12 as a secret
        BigInteger v12 = new BigInteger("0").subtract(n12).mod(n);  // P2 keeps v12 as a secret

        // k1 * w3 = u13 + v13
        BigInteger n13 = new BigInteger("2e6", 16);
        BigInteger en_u13 = MtA(en_k1, w3, n13, pk1);
        BigInteger u13 = PaillierCipher.decrypt(en_u13, sk1).mod(n);    // P1 keeps u13 as a secret
        BigInteger v13 = new BigInteger("0").subtract(n13).mod(n);  // P3 keeps v13 as a secret

        // k2 * w1 = u21 + v21
        BigInteger n21 = new BigInteger("a34", 16);
        BigInteger en_u21 = MtA(en_k2, w1, n21, pk2);
        BigInteger u21 = PaillierCipher.decrypt(en_u21, sk2).mod(n);    // P2 keeps u21 as a secret
        BigInteger v21 = new BigInteger("0").subtract(n21).mod(n);  // P1 keeps v21 as a secret

        // k2 * w3 = u23 + v23
        BigInteger n23 = new BigInteger("7bc", 16);
        BigInteger en_u23 = MtA(en_k2, w3, n23, pk2);
        BigInteger u23 = PaillierCipher.decrypt(en_u23, sk2).mod(n);    // P2 keeps u23 as a secret
        BigInteger v23 = new BigInteger("0").subtract(n23).mod(n);  // P3 keeps v23 as a secret

        // k3 * w1 = u31 + v31
        BigInteger n31 = new BigInteger("9d0", 16);
        BigInteger en_u31 = MtA(en_k3, w1, n31, pk3);
        BigInteger u31 = PaillierCipher.decrypt(en_u31, sk3).mod(n);    // P3 keeps u31 as a secret
        BigInteger v31 = new BigInteger("0").subtract(n31).mod(n);  // P1 keeps v31 as a secret

        // k3 * w2 = u32 + v32
        BigInteger n32 = new BigInteger("58a", 16);
        BigInteger en_u32 = MtA(en_k3, w2, n32, pk3);
        BigInteger u32 = PaillierCipher.decrypt(en_u32, sk3).mod(n);    // P3 keeps u32 as a secret
        BigInteger v32 = new BigInteger("0").subtract(n32).mod(n);  // P2 keeps v32 as a secret

        BigInteger sigma_share1 = k1.multiply(w1).add(u12).add(v21).add(u13).add(v31).mod(n);      // P1 reveal sigma_share1
        BigInteger sigma_share2 = k2.multiply(w2).add(u21).add(v12).add(u23).add(v32).mod(n);      // P2 reveal sigma_share2
        BigInteger sigma_share3 = k3.multiply(w3).add(u31).add(v13).add(u32).add(v23).mod(n);      // P3 reveal sigma_share3

        // s = k * (m + x * r)
        // si = m * ki + r * sigma_sharei,  s = s1 + s2 + s3
        BigInteger m = new BigInteger(message,16);

        BigInteger s1 = m.multiply(k1).add(r.multiply(sigma_share1)).mod(n);
        BigInteger s2 = m.multiply(k2).add(r.multiply(sigma_share2)).mod(n);
        BigInteger s3 = m.multiply(k3).add(r.multiply(sigma_share3)).mod(n);

        BigInteger s = s1.add(s2).add(s3).mod(n);

        //================= 3.verify ===================
        acore.verify(message, r.toString(16), s.toString(16), y);

    }

    private static void ecdsaThresholdSignature23() throws HomomorphicException{
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
        ECDSAcore acore = new ECDSAcore();
        PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();

        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
        BigInteger ZERO = new BigInteger("0", 16);
        BigInteger ONE = new BigInteger("1", 16);
        BigInteger TWO = new BigInteger("2", 16);
        BigInteger THREE = new BigInteger("3", 16);


        BigInteger u1 = new BigInteger("333", 16);  // P1 kept u1 as a secret
        BigInteger u2 = new BigInteger("666", 16);  // P2 kept u2 as a secret
        BigInteger u3 = new BigInteger("999", 16);  // P3 kept u3 as a secret
        System.out.println("x: " + u1.add(u2).add(u3));

        Point y1 = acore.fastMultiply(u1);  
        Point y2 = acore.fastMultiply(u2);  
        Point y3 = acore.fastMultiply(u3);  
        Point y = acore.add(y1, acore.add(y2, y3)); 

        BigInteger a12 = new BigInteger("218", 16);
        BigInteger f11 = u1.add(a12);      
        BigInteger f12 = u1.add(a12.multiply(TWO));    
        BigInteger f13 = u1.add(a12.multiply(THREE));  

        BigInteger a22 = new BigInteger("269", 16);
        BigInteger f21 = u2.add(a22);      
        BigInteger f22 = u2.add(a22.multiply(TWO));    
        BigInteger f23 = u2.add(a22.multiply(THREE));  

        BigInteger a32 = new BigInteger("581", 16);
        BigInteger f31 = u3.add(a32);     
        BigInteger f32 = u3.add(a32.multiply(TWO));    
        BigInteger f33 = u3.add(a32.multiply(THREE));  

        BigInteger x1 = f11.add(f21).add(f31);
        BigInteger x2 = f12.add(f22).add(f32);
        BigInteger x3 = f13.add(f23).add(f33);
        System.out.println(x1);
        System.out.println(x2);
        System.out.println(x3);

  
        // f(x) = f1(x) + f2(x) + f3(x),  f(1) = x1, f(2) = x2, f(3) = x3
        // f(x) = a1 + a2 * x
        // f(x) = x1*I1(x) + x3*I3(x)
        // f(0) = x1*I1(0) + x3*I3(0)
        // f(0) = a1 = x
        // BigInteger lamda1 = (ZERO.subtract(THREE)).divide(ONE.subtract(THREE));
        BigInteger w1 = x1.multiply(ZERO.subtract(THREE)).divide(ONE.subtract(THREE)).mod(n);     // P1 keeps w1 as a secret

        // BigInteger lamda3 = (ZERO.subtract(ONE)).divide(THREE.subtract(ONE));
        BigInteger w3 = x3.multiply(ZERO.subtract(ONE)).divide(THREE.subtract(ONE)).mod(n);     // P3 keeps w3 as a secret

        System.out.println("w1+w3 : " + w1.add(w3).mod(n));

		KeyPair paillier1 = pa.generateKeyPair();		
		PaillierPublicKey pk1 = (PaillierPublicKey) paillier1.getPublic();
		PaillierPrivateKey sk1 = (PaillierPrivateKey) paillier1.getPrivate();

		// KeyPair paillier2 = pa.generateKeyPair();		
		// PaillierPublicKey pk2 = (PaillierPublicKey) paillier2.getPublic();
		// PaillierPrivateKey sk2 = (PaillierPrivateKey) paillier2.getPrivate();

		KeyPair paillier3 = pa.generateKeyPair();		
		PaillierPublicKey pk3 = (PaillierPublicKey) paillier3.getPublic();
		PaillierPrivateKey sk3 = (PaillierPrivateKey) paillier3.getPrivate();

        //================= 2.sign ===================

        BigInteger k1 = new BigInteger("716", 16);  // P1 kept k1 as a secret
        BigInteger k3 = new BigInteger("862", 16);  // P3 kept k3 as a secret

        BigInteger gamma1 = new BigInteger("534", 16);  // P1 kept k1 as a secret
        BigInteger gamma3 = new BigInteger("921", 16);  // P3 kept k3 as a secret   

        BigInteger en_k1 = PaillierCipher.encrypt(k1, pk1);
  
        BigInteger m13 = new BigInteger("896", 16);
        BigInteger en_alpha13 = MtA(en_k1, gamma3, m13, pk1);
        BigInteger alpha13 = PaillierCipher.decrypt(en_alpha13, sk1).mod(n);    // P1 keeps alpha13 as a secret
        BigInteger beta13 = new BigInteger("0").subtract(m13).mod(n);       // P3 keeps beta13 as a secret

        BigInteger en_k3 = PaillierCipher.encrypt(k3, pk3);
        BigInteger m31 = new BigInteger("178", 16);
        BigInteger en_alpha31 = MtA(en_k3, gamma1, m31, pk3);
        BigInteger alpha31 = PaillierCipher.decrypt(en_alpha31, sk3).mod(n);    // P3 keeps alpha31 as a secret
        BigInteger beta31 = new BigInteger("0").subtract(m31).mod(n);       // P1 keeps beta31 as a secret

        BigInteger delta_share1 = k1.multiply(gamma1).add(alpha13).add(beta31).mod(n);      
        // BigInteger delta_share2 = k2.multiply(gamma2).add(alpha21).add(beta12).add(alpha23).add(beta32).mod(n);     
        BigInteger delta_share3 = k3.multiply(gamma3).add(alpha31).add(beta13).mod(n);     

        BigInteger delta = delta_share1.add(delta_share3).mod(n);

        Point Gamma1 = acore.fastMultiply(gamma1);  
        // Point Gamma2 = acore.fastMultiply(gamma2);  
        Point Gamma3 = acore.fastMultiply(gamma3);  
        // 2.4.2 计算 Gamma = Gamma1 + Gamma3
        Point Gamma = acore.add(Gamma1, Gamma3);
        //2.4.3 R = k^(-1) * g = delta^(-1) * gamma * g = delta^(-1) * Gamma
        Point R = acore.fastMultiplyWithPoint(delta.modInverse(n), Gamma);
        BigInteger r = R.getX();
        System.out.println("R : " + R);
        System.out.println("r : " + r);

        // BigInteger n12 = new BigInteger("11f", 16);
        // BigInteger en_u12 = MtA(en_k1, w2, n12, pk1);
        // BigInteger u12 = PaillierCipher.decrypt(en_u12, sk1).mod(n);    // P1 keeps u12 as a secret
        // BigInteger v12 = new BigInteger("0").subtract(n12).mod(n);  // P2 keeps v12 as a secret

        BigInteger n13 = new BigInteger("2e6", 16);
        BigInteger en_u13 = MtA(en_k1, w3, n13, pk1);
        BigInteger u13 = PaillierCipher.decrypt(en_u13, sk1).mod(n);    // P1 keeps u13 as a secret
        BigInteger v13 = new BigInteger("0").subtract(n13).mod(n);  // P3 keeps v13 as a secret

        BigInteger n31 = new BigInteger("9d0", 16);
        BigInteger en_u31 = MtA(en_k3, w1, n31, pk3);
        BigInteger u31 = PaillierCipher.decrypt(en_u31, sk3).mod(n);    // P3 keeps u31 as a secret
        BigInteger v31 = new BigInteger("0").subtract(n31).mod(n);  // P1 keeps v31 as a secret

        BigInteger sigma_share1 = k1.multiply(w1).add(u13).add(v31).mod(n);      
        BigInteger sigma_share3 = k3.multiply(w3).add(u31).add(v13).mod(n);      

        BigInteger m = new BigInteger(message,16);

        BigInteger s1 = m.multiply(k1).add(r.multiply(sigma_share1)).mod(n);
        BigInteger s3 = m.multiply(k3).add(r.multiply(sigma_share3)).mod(n);

        BigInteger s = s1.add(s3).mod(n);

        //================= 3.verify ===================
        acore.verify(message, r.toString(16), s.toString(16), y);

    }

    private static BigInteger MtA (BigInteger c1, BigInteger secret2, BigInteger m, PaillierPublicKey pk) throws HomomorphicException{
        BigInteger encrypted_m = PaillierCipher.encrypt(m, pk);
        BigInteger c2 = PaillierCipher.multiply(c1, secret2, pk);
        c2 = PaillierCipher.add(c2, encrypted_m, pk);
        return c2;
    }

}




