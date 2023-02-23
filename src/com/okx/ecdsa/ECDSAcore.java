package com.okx.ecdsa;


import com.okx.ecdsa.utils.Base58;
import com.okx.ecdsa.utils.HEX;
import com.okx.ecdsa.utils.HashUtil;
import com.okx.ecdsa.utils.Pocklington;

import java.math.BigInteger;

/**
 *  ECDSA CORE
 * @author William Liu
 *  - okx
 */
public class ECDSAcore {
    // secp256k1
    // static BigInteger TWO = new BigInteger("2");
    // static BigInteger THREE = new BigInteger("3");
    // private BigInteger a= new BigInteger("0");
    // private BigInteger b= new BigInteger("7");
    // private BigInteger p= new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
    // private BigInteger n= new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
    // private BigInteger h= new BigInteger("01");
    // //The Bitcoin G point
    // private Point G = new Point(new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16),new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",16));
    
    // StarkNet
    static BigInteger TWO = new BigInteger("2");
    static BigInteger THREE = new BigInteger("3");
    private BigInteger a= new BigInteger("0000000000000000000000000000000000000000000000000000000000000001", 16);
    private BigInteger b= new BigInteger("06f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89", 16);
    private BigInteger p= new BigInteger("800000000000011000000000000000000000000000000000000000000000001", 16);
    private BigInteger n= new BigInteger("0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",16);
    private BigInteger h= new BigInteger("01");
    //The Bitcoin G point
    private Point G = new Point(new BigInteger("1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",16),new BigInteger("5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f",16));


    /**
     * 签名
     * @author William Liu
     * @param message 消息的hash
     * @param privateKey
     * @return
     */
    public String[] sign(String message,String privateKey){
        String[] signature = new String[2];
        BigInteger r, s;
        do {

            BigInteger k = new BigInteger(HashUtil.getSHA(Math.random() + System.currentTimeMillis() + "THHAhshjaYYHJSA^HGHSA", "SHA-256"), 16);
            r = fastMultiply(k).getX().mod(n);
            s = (new BigInteger(message, 16).add(new BigInteger(privateKey, 16).multiply(r))).multiply(k.modInverse(n)).mod(n);

            //standrad bitcoin signature SIG is <r><s> concatenated together.
            // We need to check s < N/2 where N is the curve order, .
            // If s>N/2, then s = N-s
//        if (n.divide(BigInteger.TWO).compareTo(s) < 0) {
//            s = n.subtract(s);
//        }

            signature[0] = r.toString(16);
            signature[1] = s.toString(16);

        }while (isValidSignature(r,s));
        return formatSign(signature);
    }

    public String[] signWithAssignedK(String message,String privateKey, BigInteger k){
        String[] signature = new String[2];
        BigInteger r, s;
        do {

            //BigInteger k = new BigInteger(HashUtil.getSHA(Math.random() + System.currentTimeMillis() + "THHAhshjaYYHJSA^HGHSA", "SHA-256"), 16);
            r = fastMultiply(k).getX().mod(p);
            s = (new BigInteger(message, 16).add(new BigInteger(privateKey, 16).multiply(r))).multiply(k.modInverse(n)).mod(n);

            //standrad bitcoin signature SIG is <r><s> concatenated together.
            // We need to check s < N/2 where N is the curve order, .
            // If s>N/2, then s = N-s
//        if (n.divide(BigInteger.TWO).compareTo(s) < 0) {
//            s = n.subtract(s);
//        }

            signature[0] = r.toString(16);
            signature[1] = s.toString(16);

        }while (isValidSignature(r,s));
        return formatSign(signature);
    }

    /**
     * signature 补0
     * @param signature
     * @return
     */
    public static String[] formatSign(String[] signature) {
        String[] sig= new String[2];
        for(int i=0;i<sig.length;i++) {
            if (signature[i].length() % 2 != 0) {
                sig[i] = "0" + signature[i];
            }else {
                sig[i] = signature[i];
            }
        }

        return sig;
    }

    /**
     * 验证签名正确性，兼容Ethereum,符合BIP0062
     * see https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures
     * @param r
     * @param s
     * @return
     */
    public boolean isValidSignature(BigInteger r,BigInteger s){
//        boolean flag = false;
//        String sS = s.toString(16);
//        if(r.toString(16).length()==64 && s.toString(16).length()==64 ){
//            flag = true;
//        }

        return n.divide(new BigInteger("2")).compareTo(s) < 0;
    }


//    public void sign(byte[] message,String privateKey,Point publicKeyPoint){
//        BigInteger k = new BigInteger("6b99",16);
//        r = fastMultiply(k).getX().mod(p);
//        s = (new BigInteger(HEX.decode(message),16).add(new BigInteger(privateKey,16).multiply(r))).multiply(k.modInverse(n)).mod(n);
//        System.out.println("r: "+r.toString() + " s: "+s.toString());
//    }
//
//    public void signeth(byte[] message,String privateKey,Point publicKeyPoint){
//        BigInteger k = new BigInteger("f17855954749dd1275ef93ce033f52c355feb3ee2ac070cc31bd57c195e3aff7",16);
//        Point z = fastMultiply(k);
//        r = z.getX().mod(p);
//        s = new BigInteger(message).add(new BigInteger(privateKey,16).multiply(r)).multiply(k.modInverse(n)).mod(n);
//        if(z.getY().mod(new BigInteger("2")).intValue() == 0){
//            System.out.println("k: 0");
//        }else {
//            System.out.println("k: 1");
//        }
//        System.out.println("r: "+r.toString(16) + " s: "+s.toString(16));
//    }

    /**
     * verify method
     * @author William Liu
     * @param message
     * @param rS
     * @param sS
     * @param publicKeyPoint
     */
    public void verify(String message,String rS,String sS,Point publicKeyPoint){
        BigInteger r = new BigInteger(rS,16);
        BigInteger s = new BigInteger(sS,16);
        BigInteger w = s.modInverse(n);
        BigInteger u1 = w.multiply(new BigInteger(message,16)).mod(n);
        BigInteger u2 = w.multiply(r).mod(n);
        Point point = add(fastMultiply(u1),fastMultiplyWithPoint(u2,publicKeyPoint));
        System.out.println(publicKeyPoint);
        System.out.println(point);
        if(r.equals(point.getX().mod(n))){
            System.out.println("Verifyed");
        }else {
            System.out.println("error!");
        }
    }


    public Point fastMultiply(BigInteger d){
        Point point = G;
        String dIn = d.toString(2);
        for (int i = 1; i < dIn.length(); i++) {
            int bit = Integer.parseInt(dIn.substring(i,i+1));
            point = times2(point);
            if (bit==1){point = add(point,G);}
        }
        return point;
    }

    /**
     * point add method 点加法
     * @param pointG
     * @param pointQ
     * @return
     */
    public Point add(Point pointG,Point pointQ){
        Point returnPoint = null;
        if(pointG.equals(pointQ)){returnPoint = times2(pointG);}
        else if (pointG.equals(Point.POINT_AT_INFINITY)){returnPoint = pointQ;}
        else if (pointQ.equals(Point.POINT_AT_INFINITY)){returnPoint = pointG;}
        else if (isInverse(pointG,pointQ)){returnPoint = Point.POINT_AT_INFINITY;}
        else {
            BigInteger s = pointQ.getY().subtract(pointG.getY()).mod(p).multiply((pointQ.getX().subtract(pointG.getX())).modInverse(p));
            BigInteger pointX = s.multiply(s).subtract(pointG.getX()).subtract(pointQ.getX()).mod(p);
            BigInteger pointY = (s.multiply(pointG.getX().subtract(pointX))).subtract(pointG.getY()).mod(p);
            returnPoint = new Point(pointX,pointY);
        }
        return  returnPoint;
    }

    /**
     * point double method 点乘法
     * @param pointG
     * @return
     */
    public Point times2(Point pointG){
        Point returnPoint = null;
        if(pointG.equals(Point.POINT_AT_INFINITY)){ returnPoint = pointG;}else {
            BigInteger s = (THREE.multiply(pointG.getX().modPow(TWO,p)).add(a)).mod(p).multiply(TWO.multiply(pointG.getY()).modInverse(p));
            BigInteger pointX = s.multiply(s).subtract(pointG.getX()).subtract(pointG.getX()).mod(p);
            BigInteger pointY = (s.multiply(pointG.getX().subtract(pointX))).subtract(pointG.getY()).mod(p);
            returnPoint = new Point(pointX,pointY);
        }

        return returnPoint;
    }

    public boolean isInverse(Point pointG,Point pointT){
        return (p.compareTo(pointT.getY().add(pointG.getY())) == 0 && pointG.getX().compareTo(pointT.getX()) == 0);
    }

    /**
     * 判断坐标点是否在椭圆曲线上
     * @param point
     * @return
     */
    public boolean inPointOnCurve(Point point){
        return point.getY().multiply(point.getY()).mod(p).equals((point.getX().multiply(point.getX()).multiply(point.getX())).add((a.multiply(point.getX()))).add(b).mod(p));
    }

    public Point fastMultiplyWithPoint(BigInteger d,Point pointG){
        Point point = new Point(pointG.getX(),pointG.getY());
        String dIn = d.toString(2);
        for (int i = 1; i < dIn.length(); i++) {
            int bit = Integer.parseInt(dIn.substring(i,i+1));
            point = times2(point);
            if (bit==1){point = add(point,pointG);}
        }
        return point;
    }



    public int calculateV(Point R, int chainId) {
        int recoverId = R.getY().mod(new BigInteger("2")).intValue();
        int v = chainId == 1 ? recoverId + 27 : chainId * 2 + 35 + recoverId;
        return v;
    };

    // 恢复紧凑编码 64 bytes 签名对应的公钥
    public Point recoverPubkeyCompactEncoded(String message, String r, String vs, int chainId) {
        String firstHex = vs.substring(0, 1);

        int recoverId = Integer.parseInt(firstHex,16) >> 3;
        int v = chainId == 1 ? recoverId + 27 : chainId * 2 + 35 + recoverId;

        String s1 = String.valueOf(Integer.parseInt(firstHex,16) % 8 );
        String s2 = vs.substring(1);

        String s = s1 + s2;

        return recoverPubkey(message, r, s, v, chainId);
    }

    public Point recoverPubkey(String message, String r, String s, int v, int chainId) {
        Point R = recoverR(r, v, chainId);

        // u1 = - m * r^(-1) mod n; 
        BigInteger u1 = new BigInteger("0").subtract(new BigInteger(message,16).multiply(new BigInteger(r,16).modInverse(n))).mod(n);
        // u2 = s * r^(-1) mod n;
        BigInteger u2 = new BigInteger(s,16).multiply(new BigInteger(r,16).modInverse(n)).mod(n);
        // Q = u1 * G + u2 * R
        Point Q = add(fastMultiply(u1), fastMultiplyWithPoint(u2, R));

        return Q;

    }

    public Point recoverR(String r, int v, int chainId) {
        BigInteger x = new BigInteger(r,16);
        BigInteger alpha = x.pow(3).add(a.multiply(x)).add(b).mod(p);
        BigInteger beta = Pocklington.sqrt(alpha, p);
        BigInteger y = beta;
        int recoverId = chainId == 1 ? v - 27 : v - 2 * chainId - 35;
  
        // isOdd 代表的是真实的 Rx 的奇偶性，如果与 beta 的奇偶性不同，则需要翻转
        boolean isOdd = (recoverId % 2) > 0;
        if ((y.intValue()%2 == 0) ^ (!isOdd) ) {
            y = p.subtract(y);
        }
        return new Point (x, y);
    };


}
