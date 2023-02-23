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


public class MPCtest {
         public static void main(String[] args) throws HomomorphicException{

        System.out.println("==========================  ECDSA: Classical  ====================================");
        // https://okg-block.larksuite.com/docs/docuso6z74HwtSnPJzBCA5iU6Dl
        // 公共的k计算涉及到同态加密算法和零知识证明
        ecdsaClassical();

        System.out.println("==========================  ECDSA: Schnorr single sign  ============================");
        // https://medium.com/cryptoadvance/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
        // 对 ECDSA 签名进行优化，便于批量验证签名，适用于聚合签名扩展
        schnorrSingle();

        System.out.println("==========================  ECDSA: Schnorr 2/2 sign  ===============================");
        // https://medium.com/cryptoadvance/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
        // 存在的问题：
        // 1. 对于3个或以上的多签场景，通信会比较复杂
        // 2. 存在流氓密钥攻击问题：如果在计算联合公钥时Alice提供的不是P1而是P1-P2，会导致最终的联合公钥地址就是(P1-P2)+P2 = P1,从而完全由Alice控制
        // 3. 不能使用确定性k，需要一个好的随机数生成器来生成k

        // 对于2/2签名则只需要1轮通信：
        // 1.前端将用户生成的随机点R1传给后端（P1不需要生成，但也需要传给后端）
        // 2.后端生成用户的 R2，P2，计算公共哈希 z和后端的签名 s2，并将R2，P2，z和s2传给前端
        // 3.前端可以验证z，并计算用户端的签名s1，然后合并签名 s，并计算R，然后将（R，s）合并为联合地址的签名
        schnorr22();
 
        System.out.println("==========================  ECDSA: Mulsig 2/2 sign  ===============================");
        // https://medium.com/cryptoadvance/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744
        // https://bitcointechtalk.com/scaling-bitcoin-schnorr-signatures-abe3b5c275d1
        // 解决Schnor签名中 流氓密钥攻击 的问题
        mulsig22();

        System.out.println("==========================  ECDSA: MPC 2/2 sign  ===============================");
        // https://mp.weixin.qq.com/s?__biz=MzI4MzUxMDI3NQ==&mid=2247484200&idx=1&sn=deabd67cc8741f3668a2fc07afa912fa&chksm=eb88d044dcff595258ea48079b3a41418ed5c3e45b53cc1b72d1f470a6ce76762c724d08af3a&scene=21#wechat_redirect
        // si=(h+di*r)/k, k= k1+k2
        // s = s1 + s2 - h/k = (h+(d1+d2)*r)/k
        // 需要处理整数除法截断的问题和k值暴露的问题
        // 后面的推导过程涉及到 （1/k)*G, 1/k 为k的模逆
        ecdsaMpc();


        System.out.println("==========================  ECDSA: Lindell signle sign  ===============================");
        // https://medium.com/cryptoadvance/ecdsa-is-not-that-bad-two-party-signing-without-schnorr-or-bls-1941806ec36f
        // https://eprint.iacr.org/2017/552.pdf
        // P1=pk1×G、P2=pk2×G
        // R1=k1×G 、 R2=k2×G
        // P=pk1×P2=pk2×P1=pk1⋅pk2×G
        // R=k1×R2=k2×R1=k1⋅k2×G
        // s=(z+r⋅pk1⋅pk2)/k1/k2
        lindellSingle();

        System.out.println("==========================  ECDSA: Lindell 2/2 sign  ===============================");
        // https://medium.com/cryptoadvance/ecdsa-is-not-that-bad-two-party-signing-without-schnorr-or-bls-1941806ec36f
        // https://eprint.iacr.org/2017/552.pdf
        // 使用同态加密，P1 生成 Enc(key1) 给 P2 来进行签名
        lindell22();
  
        System.out.println("==========================  Curve25519 : 2/2 sign  ===============================");
        // https://en.wikipedia.org/wiki/Curve25519
        // https://en.wikipedia.org/wiki/Montgomery_curve
        // https://medium.com/asecuritysite-when-bob-met-alice/threshold-ed25519-its-just-magical-and-fit-for-a-more-resilient-and-trusted-world-5431e124942
        // https://crypto.stackexchange.com/questions/50448/schnorr-signatures-multisignature-support#
        // https://bitcointechtalk.com/scaling-bitcoin-schnorr-signatures-abe3b5c275d1
        // 基于蒙哥马利曲线结合mulsig schnorr算法的签名算法实现
        // y^2 = x^3 + 486662 * x^2 + x
        curve25519Sign22();

        System.out.println("==========================  Ed25519 : 2/2 sign  ===============================");
        // https://en.wikipedia.org/wiki/EdDSA#Ed25519
        // https://en.wikipedia.org/wiki/Twisted_Edwards_curve
        // http://ed25519.cr.yp.to/eddsa-20150704.pdf
        // https://master--eager-lamarr-59a89f.netlify.app/2018/12/28/cryptography/ed25519/
        // 基于扭曲爱德华曲线接合mulsig schnorr算法的签名算法实现
        // −x² + y² = 1 − (121665/121666) * x² * y²
        ed25519Sign22();




     





    }






    // =================================================================

    private static void ecdsaClassical() {

        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);

        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
        String p1 = "888";
        String[] rs1 = acore.sign(message, p1);
        acore.verify(message, rs1[0], rs1[1], acore.fastMultiply(new BigInteger(p1,16)));

        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        String key1 = "333";
        String key2 = "555";
        BigInteger k1 = new BigInteger("3", 16); 
        BigInteger k2 = new BigInteger("5", 16); 
        
        // 2. 根据两个private key计算出联合地址
        Point point1 = acore.fastMultiply(new BigInteger(key1, 16));
        Point point2 = acore.fastMultiply(new BigInteger(key2, 16));
        Point point3 = acore.add(point1, point2);

        // 3. 计算 r = (k1*G + k2*G)的x坐标
        String r = acore.add(acore.fastMultiply(k1), acore.fastMultiply(k2)).getX().mod(n).toString(16);
        // String r_ = acore.add(acore.fastMultiply(k1), acore.fastMultiply(k2)).getX().toString(16);
        // System.out.println(r);
        // System.out.println(r_);


        // // 4. 双方分别计算s
        // BigInteger s1 = (BigInteger(message, 16) + BigInteger(key1,16)*BigInteger(r,16))/k1;
        // BigInteger s2 = (BigInteger(message, 16) + BigInteger(key2,16)*BigInteger(r,16))/k2;
        // // 5. 计算联合签名 s = s1 + s2 - (h/k),需要计算公共的k

        // 4. 计算联合签名 s = （h + (d1+d2)*r） / (k1+k2)
        BigInteger h = new BigInteger(message,16);
        // BigInteger keys = new BigInteger(key1,16).add(new BigInteger(key2,16));
        BigInteger keys = new BigInteger(p1,16);
        
        String s = (h.add(keys.multiply(new BigInteger(r,16)))).divide(k1.add(k2)).mod(n).toString(16);
        // String s_ = (h.add(keys.multiply(new BigInteger(r,16)))).divide(k1.add(k2)).toString(16);
        // System.out.println(s);
        // System.out.println(s_);
        
        // 5. 验证签名 
        acore.verify(message, r, s, point3);
    }

    private static void schnorrSingle() {
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

        // 1. 指定 私钥p0 和 随机数 k0
        String p0 = "888";
        BigInteger k0 = new BigInteger("3", 16); 

        // 2. 计算 点R = k×G
        Point r0 = acore.fastMultiply(k0);

        // 3. 计算 s = k + hash(P,R,m) ⋅ pk
        BigInteger Px0 = acore.fastMultiply(new BigInteger(p0, 16)).getX();
        BigInteger d = Px0.add(r0.getX()).add(new BigInteger(message, 16));
        String z = HashUtil.getSHA( d.toString(16) , "SHA-256");
        BigInteger s0 = k0.add((new BigInteger(z, 16)).multiply(new BigInteger(p0, 16)));

        // 4. verify s×G = R + hash(P,R,m)×P
        Point _sG = acore.fastMultiply(s0);
        Point sG_ = acore.add(r0, acore.fastMultiplyWithPoint(new BigInteger(z,16), acore.fastMultiply(new BigInteger(p0, 16))));
        System.out.println(_sG);
        System.out.println(sG_);
    }

    private static void schnorr22() {
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

       // 1. 给A和B指定key1，key2 和 随机数k1, k2
       String key1 = "333";
       String key2 = "555";
       BigInteger k1 = new BigInteger("3", 16); 
       BigInteger k2 = new BigInteger("5", 16); 

       // 2. 计算 联合公钥P 和 联合随机点R
       Point P = acore.add(acore.fastMultiply(new BigInteger(key1, 16)), acore.fastMultiply(new BigInteger(key2, 16)));
       Point R = acore.add(acore.fastMultiply(k1), acore.fastMultiply(k2));

       // 3. 计算公共哈希 z = hash(P,R,m)
       String z = HashUtil.getSHA( P.getX().add(R.getX()).add(new BigInteger(message, 16)).toString(16) , "SHA-256");

       // 4. A和B分别计算签名si = ki + hash(P,R,m) ⋅ pki, 两个签名相加得到联合签名 s
       BigInteger s1 = k1.add((new BigInteger(z, 16)).multiply(new BigInteger(key1, 16)));
       BigInteger s2 = k2.add((new BigInteger(z, 16)).multiply(new BigInteger(key2, 16)));
       BigInteger s = s1.add(s2);

       // 5. 使用 （P， s）进行验签 s×G = R + hash(P,R,m)×P
       Point _sG = acore.fastMultiply(s);
       Point sG_ = acore.add(R, acore.fastMultiplyWithPoint(new BigInteger(z,16), P));
       System.out.println(_sG);
       System.out.println(sG_);
    }



    private static void mulsig22() {
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
    
        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        String key1 = "333";
        String key2 = "555";
        BigInteger k1 = new BigInteger("3", 16); 
        BigInteger k2 = new BigInteger("5", 16); 

        // 2. 计算 公钥Pi 和 随机点Ri
        Point P1 = acore.fastMultiply(new BigInteger(key1, 16));
        Point P2 = acore.fastMultiply(new BigInteger(key2, 16));

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.add(R1, R2);

        // 3. 计算与所有公钥地址关联的hash L = hash(P1,..Pn)
        String L = HashUtil.getSHA(P1.getX().add(P2.getX()).toString(16), "SHA-256");

        // 4. 计算聚合公钥 P=hash(L,P1)×P1+…+hash(L,Pn)×Pn
        BigInteger hash = new BigInteger(HashUtil.getSHA(new BigInteger(L,16).add(P1.getX()).toString(16), "SHA-256"), 16);
        System.out.println("hash:"+hash);

        Point _P1 = acore.fastMultiplyWithPoint(new BigInteger(HashUtil.getSHA(new BigInteger(L,16).add(P1.getX()).toString(16), "SHA-256"), 16), P1);
        Point _P2 = acore.fastMultiplyWithPoint(new BigInteger(HashUtil.getSHA(new BigInteger(L,16).add(P2.getX()).toString(16), "SHA-256"), 16), P2);
        Point P = acore.add(_P1, _P2);

        // 5. 计算公共哈希 z = H(P, R, m)
        String z = HashUtil.getSHA(P.getX().add(R.getX()).add(new BigInteger(message, 16)).toString(16) , "SHA-256");

        // 6. 计算各自的 签名 si = ki + hash(P,R,m) ⋅ hash(L,Pi) ⋅ pki, 联合签名 s = s1 + s2
        String z1_ = HashUtil.getSHA(new BigInteger(L,16).add(P1.getX()).toString(16),"SHA-256");
        String z2_ = HashUtil.getSHA(new BigInteger(L,16).add(P2.getX()).toString(16),"SHA-256");
        BigInteger s1 = k1.add(new BigInteger(z,16).multiply(new BigInteger(z1_, 16)).multiply(new BigInteger(key1, 16)));
        BigInteger s2 = k2.add(new BigInteger(z,16).multiply(new BigInteger(z2_, 16)).multiply(new BigInteger(key2, 16)));
        BigInteger s = s1.add(s2);

        // 7. 验签 s*G = R + H(P, R, m) * P
        Point _sG = acore.fastMultiply(s);
        Point sG_ = acore.add(R, acore.fastMultiplyWithPoint(new BigInteger(z,16), P));
        System.out.println(_sG);
        System.out.println(sG_);

    }


    private static void ecdsaMpc() {
        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        BigInteger key1 = new BigInteger("333", 16);
        BigInteger key2 = new BigInteger("555", 16);
        BigInteger k1 = new BigInteger("3", 16); 
        BigInteger k2 = new BigInteger("5", 16); 
        
        // 2. 根据两个private key计算出联合地址
        Point point1 = acore.fastMultiply(key1);
        Point point2 = acore.fastMultiply(key2);
        Point point3 = acore.add(point1, point2);

        // 3. 计算 r = (k1*G + k2*G)的x坐标
        String r = acore.add(acore.fastMultiply(k1), acore.fastMultiply(k2)).getX().toString(16);
        
        // 4. 计算公共的 k = k1+k2
        BigInteger k = k1.add(k2);

        // 5. 计算联合签名 s = s1 + s2 - (h/k), 
        BigInteger h = new BigInteger(message,16);
        BigInteger s1 = (h.add(key1.multiply(new BigInteger(r,16))));
        BigInteger s2 = (h.add(key2.multiply(new BigInteger(r,16))));
        String s = (s1.add(s2).subtract(h)).divide(k).toString(16);

        // 6. 验证签名 
        acore.verify(message, r, s, point3);
    }

    private static void lindellSingle() {
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);

        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        BigInteger key1 = new BigInteger("333", 16);
        BigInteger key2 = new BigInteger("555", 16);
        BigInteger k1 = new BigInteger("3", 16); 
        BigInteger k2 = new BigInteger("5", 16); 
        
        // 2. 计算联合的 P 和 R
        Point P1 = acore.fastMultiply(key1);
        Point P2 = acore.fastMultiply(key2);
        Point P = acore.fastMultiply(key1.multiply(key2));
        // Point P_ = acore.fastMultiplyWithPoint(key2, P1);
        // Point P__ = acore.fastMultiplyWithPoint(key1, P2);
        // System.out.println(P);
        // System.out.println(P_);
        // System.out.println(P__);

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.fastMultiply(k1.multiply(k2));
        // Point R_ = acore.fastMultiplyWithPoint(k1, R2);
        // Point R__ = acore.fastMultiplyWithPoint(k2, R1);
        // System.out.println(R);
        // System.out.println(R_);
        // System.out.println(R__);

        String r = R.getX().mod(n).toString(16);

        // 3. 计算签名 s=(z+r⋅pk1⋅pk2)/k1/k2
        BigInteger h = new BigInteger(message,16);
        BigInteger r_ = new BigInteger(r,16);
        String s = (h.add(r_.multiply(key1).multiply(key2))).divide(k1.multiply(k2)).mod(n).toString(16);

      // 6. 验证签名 
      acore.verify(message, r, s, P);

    }

    private static void lindell22() throws HomomorphicException{
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);

        ECDSAcore acore = new ECDSAcore();
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

        // 1. 给A和B指定key1，key2 和 随机数k1, k2
        BigInteger key1 = new BigInteger("333", 16);
        BigInteger key2 = new BigInteger("555", 16);
        BigInteger k1 = new BigInteger("3", 16); 
        BigInteger k2 = new BigInteger("5", 16); 
        
        // 2. A和B各自计算的 P1，P2 和 R1，R2
        Point P1 = acore.fastMultiply(key1);
        Point P2 = acore.fastMultiply(key2);
        Point P = acore.fastMultiplyWithPoint(key2, P1);

        Point R1 = acore.fastMultiply(k1);
        Point R2 = acore.fastMultiply(k2);
        Point R = acore.fastMultiplyWithPoint(k2, R1);
        String r = R.getX().mod(n).toString(16);


        // 3. P1 将其私钥 key1 进行同态加密，得到 c1，将 c1 给 P2
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		KeyPair paillier = pa.generateKeyPair();		
		PaillierPublicKey pk = (PaillierPublicKey) paillier.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) paillier.getPrivate();
        // System.out.println("print paillier keys");
        // System.out.println(pk);
        // System.out.println(sk);

        BigInteger ckey = PaillierCipher.encrypt(key1, pk);
        // System.out.println("ckey"+ckey);
		// BigInteger key1_ = PaillierCipher.decrypt(ckey, sk);
        // System.out.println("key1_" + key1_);


        // 4. P2 使用 ckey 计算 s'=(z+r⋅ckey⋅key2)/k2
        BigInteger h = new BigInteger(message,16);

        //c1 =encrypt(ro*n + k2^(-1)*m), ro是P2生成的一个随机数，用于混淆
        BigInteger ro = new BigInteger("7",16);
        BigInteger c1 = PaillierCipher.encrypt((ro.multiply(n)).add(k2.modInverse(n).multiply(h).mod(n)), pk);

        // v = k2^(-1)*r*key2
        BigInteger v = k2.modInverse(n).multiply(new BigInteger(r,16)).multiply(key2).mod(n);

        // c2 = 同态乘（ckey，v)
        BigInteger c2 = PaillierCipher.multiply(ckey, v, pk); 

        // c3 = 同态加 （c1, c2）
        BigInteger c3 = PaillierCipher.add(c1, c2, pk);



        // 5. P1 同态解密c3得到s_, s= k1^(−1)*s_
        BigInteger s_ = PaillierCipher.decrypt(c3, sk);
        String s = k1.modInverse(n).multiply(s_).mod(n).toString(16);
        System.out.println("r:"+r);
        System.out.println("s:"+s);

        // 6. 验证签名 
        acore.verify(message, r, s, P);

    }


    private static void curve25519Sign22() {
        BigInteger n = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
        Curve25519core acore = new Curve25519core();

        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";

        // 1. Alice 和 Bob 分别通过种子生成密钥对 
        BigInteger seed1 = new BigInteger("26666");
        String[] keys1 = acore.generateKeyPair(seed1);
        // System.out.println("keyPair:"+keys1[0]);
        // System.out.println("keyPair:"+keys1[1]);
        // System.out.println("keyPair:"+keys1[2]);

        BigInteger seed2 = new BigInteger("29999");
        String[] keys2 = acore.generateKeyPair(seed2);
        // System.out.println("keyPair:"+keys2[0]);
        // System.out.println("keyPair:"+keys2[1]);
        // System.out.println("keyPair:"+keys2[2]);

        // 2. 计算与所有公钥地址关联的hash L = hash(P1,..Pn)
        String L = HashUtil.getSHA(keys1[1] + keys2[1], "SHA-512");
        // System.out.println("L:"+L);


        // 3. 计算聚合公钥 P=hash(L,P1)×P1+…+hash(L,Pn)×Pn
        Point P1 = acore.fastMultiply(new BigInteger(keys1[0], 16));
        Point P2 = acore.fastMultiply(new BigInteger(keys2[0], 16));

        // System.out.println("P1:"+P1);
        // System.out.println("P2:"+P2);

        // 计算各自的哈希 seperateHash1, seperateHash2
        BigInteger seperateHash1 = new BigInteger(HashUtil.getSHA(L + P1.getX().toString(16), "SHA-512"),16).mod(n);
        BigInteger seperateHash2 = new BigInteger(HashUtil.getSHA(L + P2.getX().toString(16), "SHA-512"),16).mod(n);
        
        // System.out.println("seperateHash1:"+seperateHash1);
        // System.out.println("seperateHash2:"+seperateHash2);

        Point P1_ = acore.fastMultiplyWithPoint(seperateHash1, P1);
        Point P2_ = acore.fastMultiplyWithPoint(seperateHash2, P2);

        Point P = acore.add(P1_, P2_);        

        // 4. 生成随机数 r1, r2, ri = hash(privateKeyi, message)
        BigInteger r1 = new BigInteger(HashUtil.getSHA(keys1[2] + message, "SHA-512"),16).mod(n);
        BigInteger r2 = new BigInteger(HashUtil.getSHA(keys2[2] + message, "SHA-512"),16).mod(n);

        Point R1 = acore.fastMultiply(r1);
        Point R2 = acore.fastMultiply(r2);
        Point R = acore.add(R1, R2);

        // 5. 计算公共哈希 z = H(P, R, m)
        BigInteger z = new BigInteger(HashUtil.getSHA(P.getX().toString(16) + R.getX().toString(16) + message, "SHA-512"),16);

        // 6. 各自计算签名 si = ri + hash(P,R,m) ⋅ hash(L,Pi) ⋅ pki, 联合签名 s = s1 + s2
        BigInteger s1 = r1.add(z.multiply(seperateHash1).multiply(new BigInteger(keys1[0],16))).mod(n);
        BigInteger s2 = r2.add(z.multiply(seperateHash2).multiply(new BigInteger(keys2[0],16))).mod(n);

        BigInteger s = s1.add(s2);

        // 7. 验签 s*G = R + H(P, R, m) * P
        Point _sG = acore.fastMultiply(s);
        Point sG_ = acore.add(R, acore.fastMultiplyWithPoint(z, P));
        System.out.println(_sG);
        System.out.println(sG_);

    }

    private static void ed25519Sign22() {
        ED25519core acore = new ED25519core();

        BigInteger n = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
        BigInteger Eight = new BigInteger("8");
        String message = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";


        // 1. Alice 和 Bob 分别通过种子生成密钥对 
        BigInteger seed1 = new BigInteger("26666");
        String[] keys1 = acore.generateKeyPair(seed1);
        // System.out.println("keyPair:"+keys1[0]);
        // System.out.println("keyPair:"+keys1[1]);
        // System.out.println("keyPair:"+keys1[2]);

        BigInteger seed2 = new BigInteger("29999");
        String[] keys2 = acore.generateKeyPair(seed2);
        // System.out.println("keyPair:"+keys2[0]);
        // System.out.println("keyPair:"+keys2[1]);
        // System.out.println("keyPair:"+keys2[2]);

        // 2. 计算与所有公钥地址关联的hash L = hash(P1,..Pn)
        String L = HashUtil.getSHA(keys1[1] + keys2[1], "SHA-512");
        // System.out.println("L:"+L);


        // 3. 计算聚合公钥 P=hash(L,P1)×P1+…+hash(L,Pn)×Pn
        Point P1 = acore.fastMultiply(new BigInteger(keys1[0], 16));
        Point P2 = acore.fastMultiply(new BigInteger(keys2[0], 16));

        // System.out.println("P1:"+P1);
        // System.out.println("P2:"+P2);

        // 计算各自的哈希 seperateHash1, seperateHash2
        BigInteger seperateHash1 = new BigInteger(HashUtil.getSHA(L + P1.getX().toString(16), "SHA-512"),16).mod(n);
        BigInteger seperateHash2 = new BigInteger(HashUtil.getSHA(L + P2.getX().toString(16), "SHA-512"),16).mod(n);
        
        // System.out.println("seperateHash1:"+seperateHash1);
        // System.out.println("seperateHash2:"+seperateHash2);

        Point P1_ = acore.fastMultiplyWithPoint(seperateHash1, P1);
        Point P2_ = acore.fastMultiplyWithPoint(seperateHash2, P2);

        Point P = acore.add(P1_, P2_);        

        // 4. 生成随机数 r1, r2, ri = hash(privateKeyi, message)
        BigInteger r1 = new BigInteger(HashUtil.getSHA(keys1[2] + message, "SHA-512"),16).mod(n);
        BigInteger r2 = new BigInteger(HashUtil.getSHA(keys2[2] + message, "SHA-512"),16).mod(n);

        Point R1 = acore.fastMultiply(r1);
        Point R2 = acore.fastMultiply(r2);
        Point R = acore.add(R1, R2);

        // 5. 计算公共哈希 z = H(P, R, m)
        BigInteger z = new BigInteger(HashUtil.getSHA(P.getX().toString(16) + R.getX().toString(16) + message, "SHA-512"),16);

        // 6. 各自计算签名 si = ri + hash(P,R,m) ⋅ hash(L,Pi) ⋅ pki, 联合签名 s = s1 + s2
        BigInteger s1 = r1.add(z.multiply(seperateHash1).multiply(new BigInteger(keys1[0],16))).mod(n);
        BigInteger s2 = r2.add(z.multiply(seperateHash2).multiply(new BigInteger(keys2[0],16))).mod(n);

        BigInteger s = s1.add(s2);

        // 7. 验签 8*s*G = 8*R + 8*H(P, R, m) * P
        Point _sG = acore.fastMultiply(Eight.multiply(s));
        Point sG_ = acore.add(acore.fastMultiplyWithPoint(Eight,R), acore.fastMultiplyWithPoint(Eight.multiply(z), P));
        System.out.println(_sG);
        System.out.println(sG_);

    }





}
