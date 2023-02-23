package testcase;

import com.okx.ecdsa.utils.Pocklington;
import java.math.BigInteger;

public class PocklingtonTest {
         public static void main(String[] args) {
            Pocklington pock = new Pocklington();
            BigInteger a;
            BigInteger p;
            BigInteger x;

            System.out.println("============== case0 ==============");
            // a = 43, p = 47 = 4 * 11 + 3
            a = new BigInteger("43");
            p = new BigInteger("47");
            x = pock.sqrt(a, p);
            System.out.println("x: " + x);

            // a = 18, p = 23 = 4 * 5 + 3
            a = new BigInteger("18");
            p = new BigInteger("23");
            x = pock.sqrt(a, p);
            System.out.println("x: " + x);

            System.out.println("============== case1 ==============");
            // a = 10, p = 13 = 8 * 1 + 5
            a = new BigInteger("10");
            p = new BigInteger("13");
            x = pock.sqrt(a, p);
            System.out.println("x: " + x);


            System.out.println("============== case2 ==============");
            // a = 13, p = 17 = 8 * 2 + 1
            a = new BigInteger("13");
            p = new BigInteger("17");
            x = pock.sqrt(a, p);
            System.out.println("x: " + x);



    }





}
