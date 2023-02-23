package testcase;

import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.Point;
import com.okx.ecdsa.utils.PrivateKeyUtil;
import security.misc.HomomorphicException;
import java.math.BigInteger;

public class StarkEcTest {
    // =========== party_a_order =============
    // private static final String PRI_KEY = "3c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc";
    // public static final String PUB_KEY = "77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43";
    // public static final String r = "173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882";
    // public static final String s = "4b6d75385aed025aa222f28a0adc6d58db78ff17e51c3f59e259b131cd5a1cc";
    // public static final String msgHash = "397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f";

    // ============ party_b_order =============
    // private static final String PRI_KEY = "4c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc";
    // public static final String PUB_KEY = "3d8a9687c613b2be32b55c5c0460e012b592e2fbbb4fc281fb87b0d8c441b3e";
    // public static final String r = "2ee2b8927122f93dd5fc07a11980f0fab4c8358e5d1306bfee5e095355d2ad0";
    // public static final String s = "64d393473af2ebab736c579ad511bf439263e4740f9ad299498bda2e75b0e9";
    // public static final String msgHash = "6adb14408452ede28b89f40ca1847eca4de6a2dd6eb2c7d6dc5584f9399586";

    // =========== transfer_order =============
    private static final String PRI_KEY = "7cc2767a160d4ea112b436dc6f79024db70b26b11ed7aa2cb6d7eef19ace703";
    public static final String PUB_KEY = "59a543d42bcc9475917247fa7f136298bb385a6388c3df7309955fcb39b8dd4";

    // r s from signature_test_data.json
    // public static final String r = "735fffa9bf371ca294c5f74c15b434684cfe7e9e0500e6a59589ef05c1fce13";
    // public static final String s = "1ddc49993ad678e2b5b80fb0e22a077b136353514f60edc3c2fc77d59dbd93e";

    // r s from sign function
    public static final String r = "4c21b3df630eab38d75b5538e8f635167f4f7107a885d7adf542a7525240323";
    public static final String s = "5eacfaa59ed1b63d75241a1dbd9256d2efbe97f9451f2cf2a2af0bad5b5ab69";

    public static final String msgHash = "6366b00c218fb4c8a8b142ca482145e8513c78e00faa0de76298ba14fc37ae7";


    public static void main(String[] args) throws HomomorphicException {
        ECDSAcore acore = new ECDSAcore();
        // 1. 随机生成你的私钥

        String privatekey = PRI_KEY;
        System.out.println("=============== 1. 随机生成私钥 =================");
        System.out.println(privatekey);

        // 2. 计算私钥对应的公钥
        Point publickey = acore.fastMultiply(new BigInteger(privatekey, 16));
        System.out.println("=============== 2. 使用椭圆曲线乘法计算公钥 =================");
        System.out.println(publickey);
        System.out.println("JS版本的PUB_KEY是否相等: " + (PUB_KEY.equals(publickey.getX().toString(16))));
        
        // // 5. 私钥签名
        // String[] signatures = acore.sign(msgHash, privatekey);
        // System.out.println("=============== 4. 签名 =================");
        // System.out.println("java r:" + signatures[0] + ", js r:" + r);
        // System.out.println("java s:" + signatures[1] + ", js s:" + s);

        // 6. 公钥验签
        System.out.println("=============== 5. 验证签名 =================");
        System.out.println("msgHash.length: " + msgHash.length());

        acore.verify(msgHash, r, s, publickey);

        // System.out.println("=============== 6. 验证签名2 =================");
        Point point1 = acore.recoverPubkey(msgHash, r, s, 27, 1);
        Point point2 = acore.recoverPubkey(msgHash, r, s, 28, 1);
        System.out.println("point2 X: " + point2.getX().toString(16));
        System.out.println("point2 Y: " + point2.getY().toString(16));

        System.out.println("point1 X: " + point1.getX().toString(16));
        System.out.println("point1 Y: " + point1.getY().toString(16));


        System.out.println("PUB_KEY: " + PUB_KEY);
        // acore.verify(msgHash, r, s, point1);
        // acore.verify(msgHash, r, s, point2);

        System.out.println(System.getProperty("java.library.path"));  

    }

}

