package testcase;

import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.Point;
import com.okx.ecdsa.utils.PrivateKeyUtil;
import security.misc.HomomorphicException;
import java.math.BigInteger;

public class ECDSAPlayground {
         public static void main(String[] args) throws HomomorphicException{
            ECDSAcore acore = new ECDSAcore();
            
            String privatekey = "8";
            System.out.println("=============== 1. generate private key =================");
            System.out.println(privatekey);

            Point publickey = acore.fastMultiply(new BigInteger(privatekey, 16));
            System.out.println("=============== 2. get public key =================");
            System.out.println(publickey);
        
            // btc : 1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb
            // eth : 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69
            System.out.println("=============== 3. get btc address and eth address =================");
            System.out.println("btc address:" + PrivateKeyUtil.getBtcMainNetAddressWithPublickey(publickey));
            System.out.println("eth address" + PrivateKeyUtil.getEthereumAddressWithPublicKey(publickey));
            
            String transaction = "359d88771ebbbdefd2356a805af66b4243ab5ca30bb34fe154a0bd49fc4b9b40";
            
            String[] signatures = acore.sign(transaction, privatekey);
            System.out.println("=============== 4. sign =================");
            System.out.println("r:" + signatures[0]);
            System.out.println("s:" + signatures[1]);


            System.out.println("=============== 5. verify =================");
            acore.verify(transaction,signatures[0],signatures[1],publickey);

            System.out.println("=============== 6. recover =================");

            Point Q1 = acore.recoverPubkey(transaction,signatures[0],signatures[1],27,1);
            Point Q2 = acore.recoverPubkey(transaction,signatures[0],signatures[1],28,1);
            System.out.println("Q1:"+Q1);
            System.out.println("Q2:"+Q2);




    }





}
