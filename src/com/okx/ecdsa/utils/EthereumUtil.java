package com.okx.ecdsa.utils;

import java.math.BigInteger;

public class EthereumUtil {
    /**
     *
     * @param func
     * @return
     */
    public static String funcHash(String func) {
        return byte4(HashUtil.keccak256String(func));
    }

    /**
     *
     * @param data
     * @return
     */
    public static String byte4(String data) {
        return data.substring(0, 8);
    }

    /**
     * @param number
     * @return
     */
    public static String number2Byte32(BigInteger number) {
        String hex = number.toString(16);
        for (int i = hex.length(); i < 64; i++) {
            hex = "0" + hex;
        }
        return hex;
    }

    /**
     * @param address
     * @return
     */
    public static String address2Byte32(String address) {
        address = address.replaceAll("0x","");
        for (int i = address.length(); i < 64; i++) {
            address = "0" + address;
        }
        return address;
    }

    /**
     * @param hex
     * @return
     */
    public static String hex2Byte32(String hex){
        for (int i = hex.length(); i < 64; i++) {
            hex = hex + "0";
        }
        return hex;
    }

    /**
     * ABI
     * dynamic
     * bytes
     * string
     * T[] for any T
     * T[k] for any dynamic T and any k >= 0
     * (T1,...,Tk) if Ti is dynamic for some 1 <= i <= k
     * @param funcName
     * @return
     */
    public static boolean isDynamic(String funcName){
        boolean flag = false;
        if(funcName.contains("bytes")){
            flag = true;
        }

        if(funcName.contains("string")){
            flag = true;
        }

        if(funcName.contains("[")){
            flag = true;
        }

        return flag;
    }
}
