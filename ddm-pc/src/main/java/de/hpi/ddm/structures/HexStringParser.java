package de.hpi.ddm.structures;

public class HexStringParser {
    // https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    public static byte[] parse(String byteString) {
        int len = byteString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(byteString.charAt(i), 16) << 4)
                    + Character.digit(byteString.charAt(i + 1), 16));
        }
        return data;
    }


}
