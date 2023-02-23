package com.okx.ecdsa.utils;

import java.math.BigInteger;

// Pocklington method to solve x^2 = a mod p with different types of p
// https://en.wikipedia.org/wiki/Pocklington%27s_algorithm
// https://github.com/ulnesterova/finite-fields-of-odd-char
public class Pocklington {
    static BigInteger ZERO = new BigInteger("0");
    static BigInteger ONE = new BigInteger("1");
    static BigInteger TWO = new BigInteger("2");
    static BigInteger THREE = new BigInteger("3");
    static BigInteger FOUR = new BigInteger("4");
    static BigInteger FIVE = new BigInteger("5");
    static BigInteger EIGHT = new BigInteger("8");

    /**
     * Find x that fit x^2 = a mod p
     * @param a 
     * @param p 
     * @return x
     */
    public static BigInteger sqrt(BigInteger a, BigInteger p){

        if (!quadraticResidue(a, p)) {
            System.out.println("a is not quadraticResidue : " + a);
            return ZERO;
        }

        if (p.mod(FOUR).compareTo(THREE) == 0) {
            return sqrtCase0(a, p);
        }

        if (p.mod(EIGHT).compareTo(FIVE) == 0) {
            return sqrtCase1(a, p);
        }

        if (p.mod(EIGHT).compareTo(ONE) == 0) {
            return sqrtCase2(a, p);
        }

        System.out.println("pocklington error: wrong params !");
        return ZERO;

    }

    /**
     * p = 4*m + 3
     * x = ± a^(m+1)
     * @param a
     * @param p
     * @return x
     */
    private static  BigInteger sqrtCase0(BigInteger a, BigInteger p) {
        BigInteger m = p.subtract(THREE).shiftRight(2);
        return a.modPow(m.add(ONE), p); 
    }

    /**
     * p = 8*m + 5
     * if a^(2*m + 1) = 1 mod p, x = a^(m+1) mod p
     * if a^(2*m + 1) = -1 mod p, y = (4*a)^(m+1) mod p, x = y/2 (y is even ) or x = (p+y)/2 (y is odd)
     * @param a
     * @param p
     * @return x
     */
    private static  BigInteger sqrtCase1(BigInteger a, BigInteger p) {
        BigInteger m = p.subtract(FIVE).divide(EIGHT);
        BigInteger e = a.modPow(TWO.multiply(m).add(ONE),p);

        if (e.compareTo(ONE) == 0) {
            return a.modPow(m.add(ONE),p);
        }

        if (e.compareTo(p.subtract(ONE)) == 0) {
            BigInteger y = FOUR.multiply(a).modPow(TWO.multiply(m).add(ONE),p);
            if (y.mod(TWO).compareTo(ZERO) == 0) {
                return y.divide(TWO);
            } else {
                return p.add(y).divide(TWO);
            }
        }

        System.out.println("pocklington error: error in sqrt case1!");
        return ZERO;

    }

    /**
     * p = 8*m + 1
     * @param a
     * @param p
     * @return x
     */
    private static  BigInteger sqrtCase2(BigInteger a, BigInteger p) {
        a = p.subtract(a);

        BigInteger c = ONE;
        BigInteger Not_Square;
        BigInteger u = Pr(p.subtract(ONE),p);

        while (true) {      
            Not_Square = (c.multiply(c).add(u.multiply(a))).mod(p);

            if (quadraticNonResidue(Not_Square, p))
            {
                break;
            }
            c = c.add(ONE);            
        }

        BigInteger pow = p.subtract(ONE).divide(FOUR);

        BigInteger[] z = new BigInteger[] {c, ONE};
        BigInteger[] y = new BigInteger[] {ONE, ZERO};

        while (pow.compareTo(ZERO) == 1) {
            if (pow.mod(TWO).compareTo(ZERO) != 0) {
                y = mult(y, z, a, p);
            }
            pow = pow.divide(TWO);
            z = mult(z, z, a, p);
        }
        BigInteger temp_g = y[1].modPow(p.subtract(TWO), p);

        return y[0].multiply(temp_g).mod(p);
    }

    private static BigInteger Pr(BigInteger r, BigInteger p) {
        if (r.compareTo(ZERO) >= 0){
            return r.mod(p);
        } else {
            return p.subtract(ZERO.subtract(r).mod(p)).mod(p);
        }
    }

    private static BigInteger[] mult(BigInteger[] x, BigInteger[] y, BigInteger a, BigInteger p) {
        return new BigInteger[] {
            Pr(x[0].multiply(y[0]).add(x[1].multiply(y[1]).multiply(a)), p).mod(p),
            Pr(x[0].multiply(y[1]).add(y[0].multiply(x[1])), p).mod(p)
        };
    }
   

    private static boolean quadraticResidue(BigInteger N, BigInteger p) {
        BigInteger l = N.modPow(p.subtract(ONE).divide(TWO), p);
        BigInteger r = ONE;

        if (l.compareTo(r) == 0 ){
            return true;
        }
        return false;
    }

    private static boolean quadraticNonResidue(BigInteger N, BigInteger p) {
        BigInteger l = N.modPow(p.subtract(ONE).divide(TWO), p);
        BigInteger r = p.subtract(ONE);

        if (l.compareTo(r) == 0 ){
            return true;
        }
        return false;
    }


}
