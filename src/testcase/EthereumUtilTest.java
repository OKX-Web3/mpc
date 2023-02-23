package testcase;

import com.okx.ecdsa.utils.EthereumUtil;

import java.math.BigInteger;

public class EthereumUtilTest {
    public static void main(String[] args) {
        testFuncHash();
    }

    /**
     * 0000000000000000000000000000000000000000000000008ac7230489e7ffff
     * 0000000000000000000000000000000000000000000000000000000000000000
     * 000000000000000000000000CA35b7d915458EF540aDe6068dFe2F44E8fa733c
     * 000000000000000000000000CA35b7d915458EF540aDe6068dFe2F44E8fa733c
     * aaab080000000000000000000000000000000000000000000000000000000000
     */
    private static void testNumber2Byte32() {
        System.out.println(EthereumUtil.number2Byte32(new BigInteger("9999999999999999999")));
        System.out.println(EthereumUtil.address2Byte32("0x"));
        System.out.println(EthereumUtil.address2Byte32("0xCA35b7d915458EF540aDe6068dFe2F44E8fa733c"));
        System.out.println(EthereumUtil.address2Byte32("CA35b7d915458EF540aDe6068dFe2F44E8fa733c"));
        System.out.println(EthereumUtil.hex2Byte32("aaab08"));
    }

    /**
     * changeShares(address,uint256)  5634c592
     * getBalance(address)  f8b2cb4f
     * addA(uint256[]) a91d99d2
     */
    public static void testFuncHash(){
        System.out.println(EthereumUtil.funcHash("changeShares(address,uint256)"));
        System.out.println(EthereumUtil.funcHash("getBalance(address)"));
        System.out.println(EthereumUtil.funcHash("addA(uint256[])"));
    }
}
