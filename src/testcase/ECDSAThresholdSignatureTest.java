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

        //================= 1. 生成密钥分片 ===================

        // 1.1 P1, P2, P3三方各自提供随机数 ui
        BigInteger u1 = new BigInteger("333", 16);  // P1 kept u1 as a secret
        BigInteger u2 = new BigInteger("666", 16);  // P2 kept u2 as a secret
        BigInteger u3 = new BigInteger("999", 16);  // P3 kept u3 as a secret
        System.out.println("聚合私钥 x: " + u1.add(u2).add(u3));

        // 1.2 三方根据各自的ui计算对应的yi，yi = ui * g, 计算 聚合公钥 y = y1 + y2 + y3
        Point y1 = acore.fastMultiply(u1);  // P1 公开 y1
        Point y2 = acore.fastMultiply(u2);  // P2 公开 y2
        Point y3 = acore.fastMultiply(u3);  // P3 公开 y3
        Point y = acore.add(y1, acore.add(y2, y3)); // y 为聚合公钥

        // 1.3 P1 以 u1 为secret，通过随机生成一个二阶多项式计算 (2,3) Sharmir 分片，f1(x) = a11 + a12 * x + a13 * x^2, a11 = u1
        // 1.3.1 P1随机生成秘密的 a12, a13
        BigInteger a12 = new BigInteger("218", 16);
        BigInteger a13 = new BigInteger("526", 16);
        // 1.3.2 P1 计算 f1(1), f1(2), f1(3)， 并将 f1(2)分发给 P2， 将f1(3)分发给 P3
        BigInteger f11 = u1.add(a12).add(a13);      // P1 保留
        BigInteger f12 = u1.add(a12.multiply(TWO)).add(a13.multiply(TWO.multiply(TWO)));    // 分发给P2
        BigInteger f13 = u1.add(a12.multiply(THREE).add(a13.multiply(THREE.multiply(THREE))));  // 分发给P3

        // 1.4 P2 以 u2 为 secret，按照1.3的方式生成并分发分片
        BigInteger a22 = new BigInteger("269", 16);
        BigInteger a23 = new BigInteger("317", 16);
        BigInteger f21 = u2.add(a22).add(a23);      // 分发给 P1
        BigInteger f22 = u2.add(a22.multiply(TWO)).add(a23.multiply(TWO.multiply(TWO)));    // P2 保留
        BigInteger f23 = u2.add(a22.multiply(THREE).add(a23.multiply(THREE.multiply(THREE))));  // 分发给P3

        // 1.5 P3 以 u3 为 secret，按照1.3的方式生成并分发分片
        BigInteger a32 = new BigInteger("581", 16);
        BigInteger a33 = new BigInteger("729", 16);
        BigInteger f31 = u3.add(a32).add(a33);      // 分发给 P1
        BigInteger f32 = u3.add(a32.multiply(TWO)).add(a33.multiply(TWO.multiply(TWO)));    // 分发给P2
        BigInteger f33 = u3.add(a32.multiply(THREE).add(a33.multiply(THREE.multiply(THREE))));  // P3保留

        // 1.6 各自计算私钥分片 xi = f1i + f2i + f3i，则x1，x2，x3是 私钥 x 的 Sharmir 分片
        BigInteger x1 = f11.add(f21).add(f31);      // (1,x1),(2,x2),(3,x3)
        BigInteger x2 = f12.add(f22).add(f32);
        BigInteger x3 = f13.add(f23).add(f33);
        System.out.println(x1);
        System.out.println(x2);
        System.out.println(x3);


        // 1.7 用拉格朗日插值算法将xi映射为wi，满足 w1 + w2 + w3 = x，且 wi = lamdai * xi
        // f(x) = f1(x) + f2(x) + f3(x), 则有 f(1) = x1, f(2) = x2, f(3) = x3
        // f(x) = a1 + a2 * x + a3 * x^2
        // f(x) = x1*I1(x) + x2*I2(x) + x3*I3(x)
        // f(0) = x1*I1(0) + x2*I2(0) + x3*I3(0)
        // f(0) = a1 = x
        // 因此有 lamdai = Ii(0)
        BigInteger lamda1 = (ZERO.subtract(TWO)).multiply(ZERO.subtract(THREE)).divide(ONE.subtract(TWO)).divide(ONE.subtract(THREE));
        BigInteger w1 = lamda1.multiply(x1).mod(n);     // P1 keeps w1 as a secret

        BigInteger lamda2 = (ZERO.subtract(ONE)).multiply(ZERO.subtract(THREE)).divide(TWO.subtract(ONE)).divide(TWO.subtract(THREE));
        BigInteger w2 = lamda2.multiply(x2).mod(n);     // P2 keeps w2 as a secret

        BigInteger lamda3 = (ZERO.subtract(ONE)).multiply(ZERO.subtract(TWO)).divide(THREE.subtract(ONE)).divide(THREE.subtract(TWO));
        BigInteger w3 = lamda3.multiply(x3).mod(n);     // P3 keeps w3 as a secret

        // 验证私钥分片
        System.out.println("私钥分片之和 w1+w2+w3 : " + w1.add(w2).add(w3).mod(n));

        // 1.8 P1， P2，P3 分别生成各自的 Paillier 同态加密密钥
		KeyPair paillier1 = pa.generateKeyPair();		
		PaillierPublicKey pk1 = (PaillierPublicKey) paillier1.getPublic();
		PaillierPrivateKey sk1 = (PaillierPrivateKey) paillier1.getPrivate();

		KeyPair paillier2 = pa.generateKeyPair();		
		PaillierPublicKey pk2 = (PaillierPublicKey) paillier2.getPublic();
		PaillierPrivateKey sk2 = (PaillierPrivateKey) paillier2.getPrivate();

		KeyPair paillier3 = pa.generateKeyPair();		
		PaillierPublicKey pk3 = (PaillierPublicKey) paillier3.getPublic();
		PaillierPrivateKey sk3 = (PaillierPrivateKey) paillier3.getPrivate();

        //================= 2.签名 ===================

        // 2.1 P1,P2,P3各自随机生成用于签名的随机数 ki, 且聚合随机数 k = k1 + k2 + k3
        BigInteger k1 = new BigInteger("716", 16);  // P1 kept k1 as a secret
        BigInteger k2 = new BigInteger("635", 16);  // P2 kept k2 as a secret
        BigInteger k3 = new BigInteger("862", 16);  // P3 kept k3 as a secret

        // 2.2 P1,P2,P3各自随机生成另一随机数 gammai, 且 gamma = gamma1 + gamma2 + gamma3
        BigInteger gamma1 = new BigInteger("534", 16);  // P1 kept k1 as a secret
        BigInteger gamma2 = new BigInteger("678", 16);  // P2 kept k2 as a secret
        BigInteger gamma3 = new BigInteger("921", 16);  // P3 kept k3 as a secret   
        
        // 2.3 使用秘密乘法共享MtA，在不暴露各自的 ki 和gammai 的情况下计算 delta = k * gamma
        // 2.3.1 分解 k1 * gamma2 为 alpha12 + beta12
        // P1 使用 pk1 加密 k1，分发给 P2
        BigInteger en_k1 = PaillierCipher.encrypt(k1, pk1);
        // P2 生成秘密随机数 m12, 计算 en_alpha12 = homo_add(en_m12, homo_mul(en_k1, gamma1, pk1))
        BigInteger m12 = new BigInteger("586", 16);
        BigInteger en_alpha12 = MtA(en_k1, gamma2, m12, pk1);
        // P1 解密 en_alpha12 得到 alpha12, P2 保留 beta12 = -m
        BigInteger alpha12 = PaillierCipher.decrypt(en_alpha12, sk1).mod(n);    // P1 keeps alpha12 as a secret
        BigInteger beta12 = new BigInteger("0").subtract(m12).mod(n);       // P2 keeps beta12 as a secret

        // 2.3.2 分解 k1 * gamma3 为 alpha13 + beta13
        BigInteger m13 = new BigInteger("896", 16);
        BigInteger en_alpha13 = MtA(en_k1, gamma3, m13, pk1);
        BigInteger alpha13 = PaillierCipher.decrypt(en_alpha13, sk1).mod(n);    // P1 keeps alpha13 as a secret
        BigInteger beta13 = new BigInteger("0").subtract(m13).mod(n);       // P3 keeps beta13 as a secret

        // 2.3.3 分解 k2 * gamma1 为 alpha21 + beta21
        BigInteger en_k2 = PaillierCipher.encrypt(k2, pk2);
        BigInteger m21 = new BigInteger("775", 16);
        BigInteger en_alpha21 = MtA(en_k2, gamma1, m21, pk2);
        BigInteger alpha21 = PaillierCipher.decrypt(en_alpha21, sk2).mod(n);    // P2 keeps alpha21 as a secret
        BigInteger beta21 = new BigInteger("0").subtract(m21).mod(n);       // P1 keeps beta21 as a secret

        // 2.3.4 分解 k2 * gamma3 为 alpha23 + beta23
        BigInteger m23 = new BigInteger("352", 16);
        BigInteger en_alpha23 = MtA(en_k2, gamma3, m23, pk2);
        BigInteger alpha23 = PaillierCipher.decrypt(en_alpha23, sk2).mod(n);    // P2 keeps alpha23 as a secret
        BigInteger beta23 = new BigInteger("0").subtract(m23).mod(n);       // P3 keeps beta23 as a secret

        // 2.3.5 分解 k3 * gamma1 为 alpha31 + beta31
        BigInteger en_k3 = PaillierCipher.encrypt(k3, pk3);
        BigInteger m31 = new BigInteger("178", 16);
        BigInteger en_alpha31 = MtA(en_k3, gamma1, m31, pk3);
        BigInteger alpha31 = PaillierCipher.decrypt(en_alpha31, sk3).mod(n);    // P3 keeps alpha31 as a secret
        BigInteger beta31 = new BigInteger("0").subtract(m31).mod(n);       // P1 keeps beta31 as a secret

        // 2.3.6 分解 k3 * gamma2 为 alpha32 + beta32
        BigInteger m32 = new BigInteger("219", 16);
        BigInteger en_alpha32 = MtA(en_k3, gamma2, m32, pk3);
        BigInteger alpha32 = PaillierCipher.decrypt(en_alpha32, sk3).mod(n);    // P3 keeps alpha32 as a secret
        BigInteger beta32 = new BigInteger("0").subtract(m32).mod(n);       // P2 keeps beta32 as a secret
 
        BigInteger delta_share1 = k1.multiply(gamma1).add(alpha12).add(beta21).add(alpha13).add(beta31).mod(n);      // P1 公开 delta_share1
        BigInteger delta_share2 = k2.multiply(gamma2).add(alpha21).add(beta12).add(alpha23).add(beta32).mod(n);      // P2 公开 delta_share2
        BigInteger delta_share3 = k3.multiply(gamma3).add(alpha31).add(beta13).add(alpha32).add(beta23).mod(n);      // P3 公开 delta_share3

        BigInteger delta = delta_share1.add(delta_share2).add(delta_share3).mod(n);

        // 2.4 计算随机数k对应的 R = k^(-1) * g = gamma * g / (k * gamma) = gamma * g / delta
        // 2.4.1 计算 gammai * g
        Point Gamma1 = acore.fastMultiply(gamma1);  // P1 公开 Gamma1
        Point Gamma2 = acore.fastMultiply(gamma2);  // P1 公开 Gamma2
        Point Gamma3 = acore.fastMultiply(gamma3);  // P1 公开 Gamma3
        // 2.4.2 计算 Gamma = Gamma1 + Gamma2 + Gamma3
        Point Gamma = acore.add(Gamma1, acore.add(Gamma2, Gamma3));
        //2.4.3 R = k^(-1) * g = delta^(-1) * gamma * g = delta^(-1) * Gamma
        Point R = acore.fastMultiplyWithPoint(delta.modInverse(n), Gamma);
        BigInteger r = R.getX();
        System.out.println("R : " + R);
        System.out.println("r : " + r);

        // 2.5 使用秘密乘法共享MtA，在不暴露各自的 ki 和 wi 的情况下计算 sigma = k * w
        // 2.5.1 分解 k1 * w2 为 u12 + v12
        BigInteger n12 = new BigInteger("11f", 16);
        BigInteger en_u12 = MtA(en_k1, w2, n12, pk1);
        BigInteger u12 = PaillierCipher.decrypt(en_u12, sk1).mod(n);    // P1 keeps u12 as a secret
        BigInteger v12 = new BigInteger("0").subtract(n12).mod(n);  // P2 keeps v12 as a secret

        // 2.5.2 分解 k1 * w3 为 u13 + v13
        BigInteger n13 = new BigInteger("2e6", 16);
        BigInteger en_u13 = MtA(en_k1, w3, n13, pk1);
        BigInteger u13 = PaillierCipher.decrypt(en_u13, sk1).mod(n);    // P1 keeps u13 as a secret
        BigInteger v13 = new BigInteger("0").subtract(n13).mod(n);  // P3 keeps v13 as a secret

        // 2.5.3 分解 k2 * w1 为 u21 + v21
        BigInteger n21 = new BigInteger("a34", 16);
        BigInteger en_u21 = MtA(en_k2, w1, n21, pk2);
        BigInteger u21 = PaillierCipher.decrypt(en_u21, sk2).mod(n);    // P2 keeps u21 as a secret
        BigInteger v21 = new BigInteger("0").subtract(n21).mod(n);  // P1 keeps v21 as a secret

        // 2.5.4 分解 k2 * w3 为 u23 + v23
        BigInteger n23 = new BigInteger("7bc", 16);
        BigInteger en_u23 = MtA(en_k2, w3, n23, pk2);
        BigInteger u23 = PaillierCipher.decrypt(en_u23, sk2).mod(n);    // P2 keeps u23 as a secret
        BigInteger v23 = new BigInteger("0").subtract(n23).mod(n);  // P3 keeps v23 as a secret

        // 2.5.5 分解 k3 * w1 为 u31 + v31
        BigInteger n31 = new BigInteger("9d0", 16);
        BigInteger en_u31 = MtA(en_k3, w1, n31, pk3);
        BigInteger u31 = PaillierCipher.decrypt(en_u31, sk3).mod(n);    // P3 keeps u31 as a secret
        BigInteger v31 = new BigInteger("0").subtract(n31).mod(n);  // P1 keeps v31 as a secret

        // 2.5.6 分解 k3 * w2 为 u32 + v32
        BigInteger n32 = new BigInteger("58a", 16);
        BigInteger en_u32 = MtA(en_k3, w2, n32, pk3);
        BigInteger u32 = PaillierCipher.decrypt(en_u32, sk3).mod(n);    // P3 keeps u32 as a secret
        BigInteger v32 = new BigInteger("0").subtract(n32).mod(n);  // P2 keeps v32 as a secret

        BigInteger sigma_share1 = k1.multiply(w1).add(u12).add(v21).add(u13).add(v31).mod(n);      // P1 公开 sigma_share1
        BigInteger sigma_share2 = k2.multiply(w2).add(u21).add(v12).add(u23).add(v32).mod(n);      // P2 公开 sigma_share2
        BigInteger sigma_share3 = k3.multiply(w3).add(u31).add(v13).add(u32).add(v23).mod(n);      // P3 公开 sigma_share3

        // s = k * (m + x * r)
        // 2.6 各方各自计算签名 si = m * ki + r * sigma_sharei, 聚合签名 s = s1 + s2 + s3
        BigInteger m = new BigInteger(message,16);

        BigInteger s1 = m.multiply(k1).add(r.multiply(sigma_share1)).mod(n);
        BigInteger s2 = m.multiply(k2).add(r.multiply(sigma_share2)).mod(n);
        BigInteger s3 = m.multiply(k3).add(r.multiply(sigma_share3)).mod(n);

        BigInteger s = s1.add(s2).add(s3).mod(n);

        //================= 3.验签 ===================
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

        //================= 1. 生成密钥分片 ===================

        // 1.1 P1, P2, P3三方各自提供随机数 ui, 不是私钥
        BigInteger u1 = new BigInteger("333", 16);  // P1 kept u1 as a secret
        BigInteger u2 = new BigInteger("666", 16);  // P2 kept u2 as a secret
        BigInteger u3 = new BigInteger("999", 16);  // P3 kept u3 as a secret
        System.out.println("聚合私钥 x: " + u1.add(u2).add(u3));

        // 1.2 三方根据各自的ui计算对应的yi，yi = ui * g, 计算 聚合公钥 y = y1 + y2 + y3
        Point y1 = acore.fastMultiply(u1);  // P1 公开 y1
        Point y2 = acore.fastMultiply(u2);  // P2 公开 y2
        Point y3 = acore.fastMultiply(u3);  // P3 公开 y3
        Point y = acore.add(y1, acore.add(y2, y3)); // y 为聚合公钥

        // 1.3 P1 以 u1 为secret，通过随机生成一个一阶多项式计算 (1,3) Sharmir 分片，f1(x) = a11 + a12 * x, a11 = u1
        // 1.3.1 P1随机生成秘密的 a12
        BigInteger a12 = new BigInteger("218", 16);
        // 1.3.2 P1 计算 f1(1), f1(2), f1(3)， 并将 f1(2)分发给 P2， 将f1(3)分发给 P3
        BigInteger f11 = u1.add(a12);      // P1 保留
        BigInteger f12 = u1.add(a12.multiply(TWO));    // 分发给P2
        BigInteger f13 = u1.add(a12.multiply(THREE));  // 分发给P3

        // 1.4 P2 以 u2 为 secret，按照1.3的方式生成并分发分片
        BigInteger a22 = new BigInteger("269", 16);
        BigInteger f21 = u2.add(a22);      // 分发给 P1
        BigInteger f22 = u2.add(a22.multiply(TWO));    // P2 保留
        BigInteger f23 = u2.add(a22.multiply(THREE));  // 分发给P3

        // 1.5 P3 以 u3 为 secret，按照1.3的方式生成并分发分片
        BigInteger a32 = new BigInteger("581", 16);
        BigInteger f31 = u3.add(a32);      // 分发给 P1
        BigInteger f32 = u3.add(a32.multiply(TWO));    // 分发给P2
        BigInteger f33 = u3.add(a32.multiply(THREE));  // P3保留

        // 1.6 各自计算私钥分片 xi = f1i + f2i + f3i，则x1，x2，x3是 私钥 x 的 (1/3) Sharmir 分片
        // 注意这里 x1 + x2 + x3 != x, 而是 xi = f(i), 这里 f 是三个私有多项式之和
        BigInteger x1 = f11.add(f21).add(f31);
        BigInteger x2 = f12.add(f22).add(f32);
        BigInteger x3 = f13.add(f23).add(f33);
        System.out.println(x1);
        System.out.println(x2);
        System.out.println(x3);

        // 假设现在由 P1，P3 两方签名，已知(1,x1),(3,x3),求(0,f(0)?)
        // 1.7 用拉格朗日插值算法将xi映射为wi，满足 w1 + w3 = x，且 wi = lamdai * xi
        // f(x) = f1(x) + f2(x) + f3(x), 则有 f(1) = x1, f(2) = x2, f(3) = x3
        // f(x) = a1 + a2 * x
        // f(x) = x1*I1(x) + x3*I3(x)
        // f(0) = x1*I1(0) + x3*I3(0)
        // f(0) = a1 = x
        // 因此有 lamdai = Ii(0)
        // BigInteger lamda1 = (ZERO.subtract(THREE)).divide(ONE.subtract(THREE));
        BigInteger w1 = x1.multiply(ZERO.subtract(THREE)).divide(ONE.subtract(THREE)).mod(n);     // P1 keeps w1 as a secret

        // BigInteger lamda3 = (ZERO.subtract(ONE)).divide(THREE.subtract(ONE));
        BigInteger w3 = x3.multiply(ZERO.subtract(ONE)).divide(THREE.subtract(ONE)).mod(n);     // P3 keeps w3 as a secret

        // 验证私钥分片
        System.out.println("私钥分片之和 w1+w3 : " + w1.add(w3).mod(n));

        // 1.8 P1， P2，P3 分别生成各自的 Paillier 同态加密密钥
		KeyPair paillier1 = pa.generateKeyPair();		
		PaillierPublicKey pk1 = (PaillierPublicKey) paillier1.getPublic();
		PaillierPrivateKey sk1 = (PaillierPrivateKey) paillier1.getPrivate();

		// KeyPair paillier2 = pa.generateKeyPair();		
		// PaillierPublicKey pk2 = (PaillierPublicKey) paillier2.getPublic();
		// PaillierPrivateKey sk2 = (PaillierPrivateKey) paillier2.getPrivate();

		KeyPair paillier3 = pa.generateKeyPair();		
		PaillierPublicKey pk3 = (PaillierPublicKey) paillier3.getPublic();
		PaillierPrivateKey sk3 = (PaillierPrivateKey) paillier3.getPrivate();

        //================= 2.签名 ===================

        // 2.1 P1,P3各自随机生成用于签名的随机数 ki, 且聚合随机数 k = k1 + k3
        BigInteger k1 = new BigInteger("716", 16);  // P1 kept k1 as a secret
        BigInteger k3 = new BigInteger("862", 16);  // P3 kept k3 as a secret

        // 2.2 P1,P3各自随机生成另一随机数 gammai, 且 gamma = gamma1 + gamma3
        BigInteger gamma1 = new BigInteger("534", 16);  // P1 kept k1 as a secret
        BigInteger gamma3 = new BigInteger("921", 16);  // P3 kept k3 as a secret   
        
        // 2.3 使用秘密乘法共享MtA，在不暴露各自的 ki 和gammai 的情况下计算 delta = k * gamma
        // // 2.3.1 分解 k1 * gamma2 为 alpha12 + beta12
        // // P1 使用 pk1 加密 k1，分发给 P2
        BigInteger en_k1 = PaillierCipher.encrypt(k1, pk1);
        // // P2 生成秘密随机数 m12, 计算 en_alpha12 = homo_add(en_m12, homo_mul(en_k1, gamma1, pk1))
        // BigInteger m12 = new BigInteger("586", 16);
        // BigInteger en_alpha12 = MtA(en_k1, gamma2, m12, pk1);
        // // P1 解密 en_alpha12 得到 alpha12, P2 保留 beta12 = -m
        // BigInteger alpha12 = PaillierCipher.decrypt(en_alpha12, sk1).mod(n);    // P1 keeps alpha12 as a secret
        // BigInteger beta12 = new BigInteger("0").subtract(m12).mod(n);       // P2 keeps beta12 as a secret

        // 2.3.2 分解 k1 * gamma3 为 alpha13 + beta13
        BigInteger m13 = new BigInteger("896", 16);
        BigInteger en_alpha13 = MtA(en_k1, gamma3, m13, pk1);
        BigInteger alpha13 = PaillierCipher.decrypt(en_alpha13, sk1).mod(n);    // P1 keeps alpha13 as a secret
        BigInteger beta13 = new BigInteger("0").subtract(m13).mod(n);       // P3 keeps beta13 as a secret

        // 2.3.3 分解 k2 * gamma1 为 alpha21 + beta21
        // BigInteger en_k2 = PaillierCipher.encrypt(k2, pk2);
        // BigInteger m21 = new BigInteger("775", 16);
        // BigInteger en_alpha21 = MtA(en_k2, gamma1, m21, pk2);
        // BigInteger alpha21 = PaillierCipher.decrypt(en_alpha21, sk2).mod(n);    // P2 keeps alpha21 as a secret
        // BigInteger beta21 = new BigInteger("0").subtract(m21).mod(n);       // P1 keeps beta21 as a secret

        // 2.3.4 分解 k2 * gamma3 为 alpha23 + beta23
        // BigInteger m23 = new BigInteger("352", 16);
        // BigInteger en_alpha23 = MtA(en_k2, gamma3, m23, pk2);
        // BigInteger alpha23 = PaillierCipher.decrypt(en_alpha23, sk2).mod(n);    // P2 keeps alpha23 as a secret
        // BigInteger beta23 = new BigInteger("0").subtract(m23).mod(n);       // P3 keeps beta23 as a secret

        // 2.3.5 分解 k3 * gamma1 为 alpha31 + beta31
        BigInteger en_k3 = PaillierCipher.encrypt(k3, pk3);
        BigInteger m31 = new BigInteger("178", 16);
        BigInteger en_alpha31 = MtA(en_k3, gamma1, m31, pk3);
        BigInteger alpha31 = PaillierCipher.decrypt(en_alpha31, sk3).mod(n);    // P3 keeps alpha31 as a secret
        BigInteger beta31 = new BigInteger("0").subtract(m31).mod(n);       // P1 keeps beta31 as a secret

        // 2.3.6 分解 k3 * gamma2 为 alpha32 + beta32
        // BigInteger m32 = new BigInteger("219", 16);
        // BigInteger en_alpha32 = MtA(en_k3, gamma2, m32, pk3);
        // BigInteger alpha32 = PaillierCipher.decrypt(en_alpha32, sk3).mod(n);    // P3 keeps alpha32 as a secret
        // BigInteger beta32 = new BigInteger("0").subtract(m32).mod(n);       // P2 keeps beta32 as a secret
 
        BigInteger delta_share1 = k1.multiply(gamma1).add(alpha13).add(beta31).mod(n);      // P1 公开 delta_share1
        // BigInteger delta_share2 = k2.multiply(gamma2).add(alpha21).add(beta12).add(alpha23).add(beta32).mod(n);      // P2 公开 delta_share2
        BigInteger delta_share3 = k3.multiply(gamma3).add(alpha31).add(beta13).mod(n);      // P3 公开 delta_share3

        BigInteger delta = delta_share1.add(delta_share3).mod(n);

        // 2.4 计算随机数k对应的 R = k^(-1) * g
        // 2.4.1 计算 gammai * g
        Point Gamma1 = acore.fastMultiply(gamma1);  // P1 公开 Gamma1
        // Point Gamma2 = acore.fastMultiply(gamma2);  // P1 公开 Gamma2
        Point Gamma3 = acore.fastMultiply(gamma3);  // P1 公开 Gamma3
        // 2.4.2 计算 Gamma = Gamma1 + Gamma3
        Point Gamma = acore.add(Gamma1, Gamma3);
        //2.4.3 R = k^(-1) * g = delta^(-1) * gamma * g = delta^(-1) * Gamma
        Point R = acore.fastMultiplyWithPoint(delta.modInverse(n), Gamma);
        BigInteger r = R.getX();
        System.out.println("R : " + R);
        System.out.println("r : " + r);

        // 2.5 使用秘密乘法共享MtA，在不暴露各自的 ki 和 wi 的情况下计算 sigma = k * w
        // 2.5.1 分解 k1 * w2 为 u12 + v12
        // BigInteger n12 = new BigInteger("11f", 16);
        // BigInteger en_u12 = MtA(en_k1, w2, n12, pk1);
        // BigInteger u12 = PaillierCipher.decrypt(en_u12, sk1).mod(n);    // P1 keeps u12 as a secret
        // BigInteger v12 = new BigInteger("0").subtract(n12).mod(n);  // P2 keeps v12 as a secret

        // 2.5.2 分解 k1 * w3 为 u13 + v13
        BigInteger n13 = new BigInteger("2e6", 16);
        BigInteger en_u13 = MtA(en_k1, w3, n13, pk1);
        BigInteger u13 = PaillierCipher.decrypt(en_u13, sk1).mod(n);    // P1 keeps u13 as a secret
        BigInteger v13 = new BigInteger("0").subtract(n13).mod(n);  // P3 keeps v13 as a secret

        // 2.5.3 分解 k2 * w1 为 u21 + v21
        // BigInteger n21 = new BigInteger("a34", 16);
        // BigInteger en_u21 = MtA(en_k2, w1, n21, pk2);
        // BigInteger u21 = PaillierCipher.decrypt(en_u21, sk2).mod(n);    // P2 keeps u21 as a secret
        // BigInteger v21 = new BigInteger("0").subtract(n21).mod(n);  // P1 keeps v21 as a secret

        // 2.5.4 分解 k2 * w3 为 u23 + v23
        // BigInteger n23 = new BigInteger("7bc", 16);
        // BigInteger en_u23 = MtA(en_k2, w3, n23, pk2);
        // BigInteger u23 = PaillierCipher.decrypt(en_u23, sk2).mod(n);    // P2 keeps u23 as a secret
        // BigInteger v23 = new BigInteger("0").subtract(n23).mod(n);  // P3 keeps v23 as a secret

        // 2.5.5 分解 k3 * w1 为 u31 + v31
        BigInteger n31 = new BigInteger("9d0", 16);
        BigInteger en_u31 = MtA(en_k3, w1, n31, pk3);
        BigInteger u31 = PaillierCipher.decrypt(en_u31, sk3).mod(n);    // P3 keeps u31 as a secret
        BigInteger v31 = new BigInteger("0").subtract(n31).mod(n);  // P1 keeps v31 as a secret

        // 2.5.6 分解 k3 * w2 为 u32 + v32
        // BigInteger n32 = new BigInteger("58a", 16);
        // BigInteger en_u32 = MtA(en_k3, w2, n32, pk3);
        // BigInteger u32 = PaillierCipher.decrypt(en_u32, sk3).mod(n);    // P3 keeps u32 as a secret
        // BigInteger v32 = new BigInteger("0").subtract(n32).mod(n);  // P2 keeps v32 as a secret

        BigInteger sigma_share1 = k1.multiply(w1).add(u13).add(v31).mod(n);      // P1 公开 sigma_share1
        // BigInteger sigma_share2 = k2.multiply(w2).add(u21).add(v12).add(u23).add(v32).mod(n);      // P2 公开 sigma_share2
        BigInteger sigma_share3 = k3.multiply(w3).add(u31).add(v13).mod(n);      // P3 公开 sigma_share3

        // 2.6 各方各自计算签名 si = m * ki + r * sigma_sharei, 聚合签名 s = s1 + s3
        BigInteger m = new BigInteger(message,16);

        BigInteger s1 = m.multiply(k1).add(r.multiply(sigma_share1)).mod(n);
        // BigInteger s2 = m.multiply(k2).add(r.multiply(sigma_share2)).mod(n);
        BigInteger s3 = m.multiply(k3).add(r.multiply(sigma_share3)).mod(n);

        BigInteger s = s1.add(s3).mod(n);

        //================= 3.验签 ===================
        acore.verify(message, r.toString(16), s.toString(16), y);

    }

    private static BigInteger MtA (BigInteger c1, BigInteger secret2, BigInteger m, PaillierPublicKey pk) throws HomomorphicException{
        BigInteger encrypted_m = PaillierCipher.encrypt(m, pk);
        BigInteger c2 = PaillierCipher.multiply(c1, secret2, pk);
        c2 = PaillierCipher.add(c2, encrypted_m, pk);
        return c2;
    }

}




