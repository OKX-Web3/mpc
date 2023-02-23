package testcase;

import com.okx.ecdsa.utils.HashUtil;
import java.math.BigInteger;

public class RSA {

    public static void main(String[] args) {
    // BigInteger ONE =  new BigInteger("1",16);
    BigInteger secp256key = new BigInteger("9b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",16);
    System.out.println("secp256key: " + secp256key);

    // expected RSA public key
    BigInteger pubkey = new BigInteger("65537");

    
    generateRSAKey(secp256key, pubkey);

    }

    private static void generateRSAKey(BigInteger secp256key, BigInteger pubkey) {
        if (!pubkey.isProbablePrime(10)) {
            System.out.println("input a pubkey which is not a prime");
            return;
        }

        // 1. get secp256key's sha512 hash;
        BigInteger hashP = new BigInteger(HashUtil.getSHA(secp256key.toString(16), "SHA-512"),16);

        // 2. make sure hashP's bit length is 512
        while(true) {
            int hashPLengh = hashP.bitLength();
            System.out.println("hashPLengh: " + hashPLengh);
            if (hashPLengh == 512){
                break;
            }
            hashP = new BigInteger(HashUtil.getSHA(hashP.toString(16), "SHA-512"),16);
        }
    
        // 3. find the next probable prime larger than hashP
        BigInteger p = hashP.nextProbablePrime();
        System.out.println("p: " + p);
        int pLengh = p.bitLength();
        System.out.println("pLengh: " + pLengh);
    
        // 4. get hashQ as hashP's sha512 hash
        BigInteger hashQ = new BigInteger(HashUtil.getSHA(hashP.toString(16), "SHA-512"),16);
        
        // 5. make sure hashQ's bit length is 512
        while(true) {
            int hashQLengh = hashQ.bitLength();
            System.out.println("hashQLengh: " + hashQLengh);
            if (hashQLengh == 512){
                break;
            }
            hashQ = new BigInteger(HashUtil.getSHA(hashQ.toString(16), "SHA-512"),16);
        }

        // 6. find the next probable prime larger than hashQ
        BigInteger q = hashQ.nextProbablePrime();
        System.out.println("q: " + q);
        int qLengh = q.bitLength();
        System.out.println("qLengh: " + qLengh);
    
        // 7. get (pubkey, n) as public key, and (prikey, n) as private key
        BigInteger p1 = p.subtract(BigInteger.ONE);
        BigInteger q1 = q.subtract(BigInteger.ONE);
        BigInteger n = p.multiply(q);
        int nLength = n.bitLength();


        BigInteger phi = p1.multiply(q1);
        BigInteger prikey = pubkey.modInverse(phi);
    
        System.out.println("n: " + n);
        System.out.println("nLength: " + nLength);
        System.out.println("pubkey: " + pubkey);
        System.out.println("prikey: " + prikey);
    
    
        // 8. encrypt and decrypt
        BigInteger message = new BigInteger("999", 16);
    
        BigInteger encrypedMsg = message.modPow(pubkey, n);
    
        BigInteger decryptedMsg = encrypedMsg.modPow(prikey, n);
    
        System.out.println("message: " + message);
        System.out.println("encrypedMsg: " + encrypedMsg);
        System.out.println("decryptedMsg: " + decryptedMsg);
    
    }





}




