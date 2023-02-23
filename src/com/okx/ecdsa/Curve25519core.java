package com.okx.ecdsa;


import com.okx.ecdsa.utils.Base58;
import com.okx.ecdsa.utils.HEX;
import com.okx.ecdsa.utils.HashUtil;

import java.math.BigInteger;

/**
 *  ECDSA CORE
 * @author William Liu
 *  - okx
 */
public class Curve25519core {
    static BigInteger ZERO = new BigInteger("0");
    static BigInteger ONE = new BigInteger("1");
    static BigInteger TWO = new BigInteger("2");
    static BigInteger THREE = new BigInteger("3");

    // hash function should have 2b-bits output
    private int b = 256;

    // B*y^2 = x^3 + A*x^2 +x
    // y^2 = x^3 + 486662 * x^2 + x
    private BigInteger A = new BigInteger("486662");
    private BigInteger B = new BigInteger("1");

    // Finite field, p = 2**255 - 19
    private BigInteger p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    // subgroup order, how many points ed25519 has, n = 2**252 + 27742317777372353535851937790883648493
    private BigInteger n = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
    // cofactor
    private BigInteger h = new BigInteger("8");

    //The Base Poing G 
    private Point G = new Point(new BigInteger("9"),new BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401"));
    // private Point NEUTRAL_POINT = new Point(ZERO, ONE);




    public String[] generateKeyPair(BigInteger seed) {
        String[] signature = new String[3];

        String h = HashUtil.getSHA(seed.toString(16),"SHA-512");

        String privateKey = new BigInteger(h.substring(0,b/4),16).toString(2); 

        privateKey = padString(privateKey);     //左边补零至256bit
        privateKey = "000" + privateKey.substring(3,254) + "10";
        privateKey = new BigInteger(privateKey,2).toString(16);

        String publicKey = fastMultiply(new BigInteger(privateKey, 16)).getX().toString(16);

        String prefix = new BigInteger(h.substring(b/4),16).toString(16);

        signature[0] = privateKey;
        signature[1] = publicKey;
        signature[2] = prefix;

        return signature;
    }

    private static String padString(String x) {
        int length = x.length();
        int pad = 256 - length;
        if (pad > 0) {
            for (int i = 0; i < pad; i ++) {
                x = "0" + x;
            }
        }
        return x;
    }





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
            BigInteger l = (pointQ.getY().subtract(pointG.getY()).mod(p).multiply((pointQ.getX().subtract(pointG.getX())).modInverse(p))).mod(p);
            BigInteger pointX = B.multiply(l).multiply(l).subtract(A).subtract(pointG.getX()).subtract(pointQ.getX()).mod(p);
            BigInteger pointY = TWO.multiply(pointG.getX()).add(pointQ.getX()).add(A).multiply(l)
                                    .subtract(B.multiply(l).multiply(l).multiply(l))
                                    .subtract(pointG.getY())
                                    .mod(p);
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
            BigInteger l = (THREE.multiply(pointG.getX().modPow(TWO,p))
                                .add(TWO.multiply(A).multiply(pointG.getX()))
                                .add(ONE)
                            ).mod(p)
                            .multiply(
                                (TWO.multiply(B).multiply(pointG.getY())).modInverse(p)
                            );
            BigInteger pointX = B.multiply(l).multiply(l).subtract(A).subtract(pointG.getX()).subtract(pointG.getX()).mod(p);
            BigInteger pointY = TWO.multiply(pointG.getX()).add(pointG.getX()).add(A).multiply(l)
                                    .subtract(B.multiply(l).multiply(l).multiply(l))
                                    .subtract(pointG.getY()
                                ).mod(p);
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
    public boolean isPointOnCurve(Point point){
        return B.multiply(point.getY()).multiply(point.getY()).mod(p).equals(
            (point.getX().multiply(point.getX()).multiply(point.getX()))
                .add((A.multiply(point.getX()).multiply(point.getX())))
                .add(point.getX()).mod(p));
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

}
