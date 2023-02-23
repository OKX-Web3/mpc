package com.okx.ecdsa;


import com.okx.ecdsa.utils.Base58;
import com.okx.ecdsa.utils.HEX;
import com.okx.ecdsa.utils.HashUtil;

import java.math.BigInteger;

/**
 *  ED25519 CORE
 * @author Jason LI
 */
public class ED25519core {
    static BigInteger ZERO = new BigInteger("0");
    static BigInteger ONE = new BigInteger("1");
    static BigInteger TWO = new BigInteger("2");
    static BigInteger THREE = new BigInteger("3");

    /**
     * ed25519 is Twisted Edwards curve with equation of
     * ```
     * ax² + y² = 1 + d * x² * y²
     * a = -1;
     * d = - (121665/121666)
     * −x² + y² = 1 − (121665/121666) * x² * y²
     * ```
     * Addition and doubling algorithm are based on wiki https://en.wikipedia.org/wiki/Twisted_Edwards_curve
     * More efficient formulars could be found in http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
     */
    private int b = 256;

    private BigInteger a = new BigInteger("-1");
    // Equal to -121665/121666 over finite field.
    // Negative number is P - number, and division is invert(number, P)
    private BigInteger d = new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555");

    // Finite field, q = 2**255 - 19
    private BigInteger q= new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    // subgroup order, how many points ed25519 has, n = 2**252 + 27742317777372353535851937790883648493
    private BigInteger n= new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
    // cofactor
    private BigInteger h= new BigInteger("8");

    //The Base Poing G 
    private Point G = new Point(new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"),new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
    private Point NEUTRAL_POINT = new Point(ZERO, ONE);


    public String[] generateKeyPair(BigInteger seed) {
        String[] signature = new String[3];

        String h = HashUtil.getSHA(seed.toString(16),"SHA-512");

        String privateKey = new BigInteger(h.substring(0,b/4),16).toString(2); 

        privateKey = padString(privateKey);    
        privateKey = "11111000" + privateKey.substring(8,248) + "10" + privateKey.substring(250);
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
     * signature
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


    public Point fastMultiply(BigInteger m){
        Point point = G;
        String dIn = m.toString(2);
        for (int i = 1; i < dIn.length(); i++) {
            int bit = Integer.parseInt(dIn.substring(i,i+1));
            point = times2(point);
            if (bit==1){point = add(point,G);}
        }
        return point;
    }



    /**
     * point add method
     * @param pointG
     * @param pointQ
     * @return
     */
    public Point add(Point point1,Point point2){
        Point returnPoint = null;
        if(point1.equals(point2)){returnPoint = times2(point1);}
        else if (point1.equals(NEUTRAL_POINT)){returnPoint = point2;}
        else if (point2.equals(NEUTRAL_POINT)){returnPoint = point1;}
        else if (isInverse(point1,point2)){returnPoint = NEUTRAL_POINT;}
        else {
            BigInteger x1 = point1.getX();
            BigInteger y1 = point1.getY();
            BigInteger x2 = point2.getX();
            BigInteger y2 = point2.getY();

            BigInteger pointX = x1.multiply(y2).add(y1.multiply(x2)).mod(q)
                                    .multiply(ONE.add(d.multiply(x1).multiply(x2).multiply(y1).multiply(y2)).modInverse(q))
                                    .mod(q);
            BigInteger pointY = y1.multiply(y2).subtract((a.multiply(x1).multiply(x2))).mod(q)
                                    .multiply(ONE.subtract(d.multiply(x1).multiply(x2).multiply(y1).multiply(y2)).modInverse(q))
                                    .mod(q);
            
            returnPoint = new Point(pointX,pointY);
        }
        return  returnPoint;
    }

    /**
     * point double method
     * @param pointG
     * @return
     */
    public Point times2(Point point){
        Point returnPoint = null;

        BigInteger x1 = point.getX();
        BigInteger y1 = point.getY();

        if(point.equals(NEUTRAL_POINT)){ returnPoint = point;}else {
            BigInteger pointX = TWO.multiply(x1).multiply(y1).mod(q)
                                    .multiply(a.multiply(x1).multiply(x1).add(y1.multiply(y1)).modInverse(q))
                                    .mod(q);

            BigInteger pointY = y1.multiply(y1).subtract(a.multiply(x1).multiply(x1)).mod(q)
                                    .multiply(TWO.subtract(a.multiply(x1).multiply(x1)).subtract(y1.multiply(y1)).modInverse(q))
                                    .mod(q);

            returnPoint = new Point(pointX,pointY);
        }
      
        return returnPoint;
    }

    public boolean isInverse(Point pointG,Point pointT){
        return (q.compareTo(pointT.getX().add(pointG.getX())) == 0 && pointG.getY().compareTo(pointT.getY()) == 0);
    }

    /**
     * ax² + y² = 1 + d * x² * y²
     * @param point
     * @return
     */
    public boolean isPointOnCurve(Point point){
        return a.multiply(point.getX()).multiply(point.getX()).add(point.getY().multiply(point.getY())).mod(q)
                    .equals(ONE.add(d.multiply(point.getX()).multiply(point.getX()).multiply(point.getY()).multiply(point.getY())).mod(q));
    }

    public Point fastMultiplyWithPoint(BigInteger m,Point pointG){
        Point point = new Point(pointG.getX(),pointG.getY());
        String dIn = m.toString(2);
        for (int i = 1; i < dIn.length(); i++) {
            int bit = Integer.parseInt(dIn.substring(i,i+1));
            point = times2(point);
            if (bit==1){point = add(point,pointG);}
        }
        return point;
    }

}
