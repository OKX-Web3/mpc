package com.okx.ecdsa.utils;

import com.okx.ecdsa.ECDSAcore;
import com.okx.ecdsa.Point;
import com.okx.ecdsa.utils.Base58;
import com.okx.ecdsa.utils.HEX;
import com.okx.ecdsa.utils.HashUtil;

import java.math.BigInteger;

public class PrivateKeyUtil {
    /**
     * see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
     * @param priv
     * @return
     */
    public static String getEthereumAddress(String priv){
        ECDSAcore acore = new ECDSAcore();
        Point publicKey = acore.fastMultiply(new BigInteger(priv,16));
        String nostan = HashUtil.keccak256(publicKey.getX().toString(16) + publicKey.getY().toString(16)).substring(24, 64);
        StringBuilder stringBuilder = new StringBuilder();
        String hex = HashUtil.keccak256String(nostan);
        for (int i=0;i<nostan.length();i++){
            if(Integer.parseInt(hex.substring(i,i+1),16) >= 8){
                stringBuilder.append(nostan.substring(i,i+1).toUpperCase());
            }else{
                stringBuilder.append(nostan.substring(i,i+1));
            }
        }
        return "0x"+stringBuilder.toString();
    }

       /**
     * see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
     * @param priv
     * @return
     */
    public static String getEthereumAddressWithPublicKey(Point publicKey){
        String nostan = HashUtil.keccak256(publicKey.getX().toString(16) + publicKey.getY().toString(16)).substring(24, 64);
        StringBuilder stringBuilder = new StringBuilder();
        String hex = HashUtil.keccak256String(nostan);
        for (int i=0;i<nostan.length();i++){
            if(Integer.parseInt(hex.substring(i,i+1),16) >= 8){
                stringBuilder.append(nostan.substring(i,i+1).toUpperCase());
            }else{
                stringBuilder.append(nostan.substring(i,i+1));
            }
        }
        return "0x"+stringBuilder.toString();
    }
    /**
     * @param priv
     * @return
     */
    public static String getBtcMainNetAddress(String priv){
        ECDSAcore acore = new ECDSAcore();
        Point publicKey = acore.fastMultiply(new BigInteger(priv,16));
        String str = "00" + HashUtil.getRipeMD160(HEX.encode(HashUtil.getSHA(getCompressedPublicKey(publicKey), "SHA-256")));
        String str2 = HashUtil.getSHA(HashUtil.getSHA(str, "SHA-256"), "SHA-256").substring(0, 8);
        return Base58.encode(HEX.encode(str+str2));
    }

        /**
     * @param priv
     * @return
     */
    public static String getBtcMainNetAddressWithPublickey(Point publicKey){
        String str = "00" + HashUtil.getRipeMD160(HEX.encode(HashUtil.getSHA(getCompressedPublicKey(publicKey), "SHA-256")));
        String str2 = HashUtil.getSHA(HashUtil.getSHA(str, "SHA-256"), "SHA-256").substring(0, 8);
        return Base58.encode(HEX.encode(str+str2));
    }



    /**
     * @param priv
     * @return
     */
    public static String getBtcTestNetAddress(String priv){
        ECDSAcore acore = new ECDSAcore();
        Point publicKey = acore.fastMultiply(new BigInteger(priv,16));
        String str = "6f" + HashUtil.getRipeMD160(HEX.encode(HashUtil.getSHA(getCompressedPublicKey(publicKey), "SHA-256")));
        String str2 = HashUtil.getSHA(HashUtil.getSHA(str, "SHA-256"), "SHA-256").substring(0, 8);
        return Base58.encode(HEX.encode(str+str2));
    }

    /**
     * @author William Liu
     * @param publicKey
     * @return
     */
    public static String getUnCompressedPublicKey(Point publicKey){
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("04");
        stringBuilder.append(publicKey.getX().toString(16));
        stringBuilder.append(publicKey.getY().toString(16));
        return  stringBuilder.toString();
    }

    /**
     * @author William Liu
     * @param publicKey
     * @return
     */
    public static String getCompressedPublicKey(Point publicKey){
        StringBuilder stringBuilder = new StringBuilder();
        if(0 == publicKey.getX().mod(new BigInteger("2")).intValue()){
            stringBuilder.append("03");
        }else{
            stringBuilder.append("02");
        }

        stringBuilder.append(publicKey.getX().toString(16));
        return  stringBuilder.toString();
    }

}
