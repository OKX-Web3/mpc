

package bls12381.BLS12381;

public class CONFIG_FIELD {
    public static final int NOT_SPECIAL = 0;
    public static final int PSEUDO_MERSENNE = 1;
    public static final int MONTGOMERY_FRIENDLY = 2;
    public static final int GENERALISED_MERSENNE = 3;

    public static final int NEGATOWER = 0;
    public static final int POSITOWER = 1;

    public static final int MODBITS = 381; /* Number of bits in Modulus */
    public static final int PM1D2 = 1; /* Modulus mod 8 */
    public static final int MODTYPE = NOT_SPECIAL;
    public static final int QNRI = 0;
    public static final int RIADZ = 11;
    public static final int RIADZG2A = -2;
    public static final int RIADZG2B = -1;
    public static final int TOWER = NEGATOWER;

    public static final boolean BIG_ENDIAN_SIGN = false;

    public static final int FEXCESS = (((int)1 << 25) - 1); // BASEBITS*NLEN-MODBITS or 2^30 max!
}
