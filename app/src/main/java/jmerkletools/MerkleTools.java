package jmerkletools;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.DatatypeConverter;

import com.google.common.primitives.Bytes;

public class MerkleTools {
    private List<byte[]> leaves;
    private List<List<byte[]>> levels;
    private Boolean is_ready;

    public MerkleTools() {
        this.resetTree();
    }

    public static String bytes2Hex(byte[] array) {
        return DatatypeConverter.printHexBinary(array);
    }

    public static byte[] hex2Bytes(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    private static String toHex(byte[] bytes) {
        return bytes2Hex(bytes);
    }

    public void resetTree() {
        this.leaves = new ArrayList<byte[]>();
        this.levels = null;
        this.is_ready = false;
    }

    public static byte[] hashSha256(String v_raw) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] v_bytes = digest.digest(v_raw.getBytes(StandardCharsets.UTF_8));
        return v_bytes;
    }

    public static byte[] hashSha256(byte[] v_raw) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] v_bytes = digest.digest(v_raw);
        return v_bytes;
    }

    public void addLeaf(List<String> values, Boolean do_hash) throws Exception {
        this.is_ready = false;
        for (String v_raw : values) {
            byte[] v_bytes;
            if (do_hash) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                v_bytes = digest.digest(v_raw.getBytes(StandardCharsets.UTF_8));

            } else {
                String v_hex = v_raw; // 如果v_raw已经是哈希后的字符串（16进制形式）
                v_bytes = hex2Bytes(v_hex);
            }
            this.leaves.add(v_bytes);
        }
    }

    public void addLeaf(List<String> values) throws Exception {
        this.addLeaf(values, false);
    }

    public String getLeaf(int index) {
        return toHex(this.leaves.get(index));
    }

    public int getLeafCount() {
        return this.leaves.size();
    }

    public Boolean getTreeReadyState() {
        return this.is_ready;
    }

    public void makeTree() throws Exception {
        this.is_ready = false;
        if (this.getLeafCount() > 0) {
            this.levels = new ArrayList<List<byte[]>>();
            this.levels.add(this.leaves);
            while (this.levels.get(0).size() > 1) {
                this.calculateNextLevel();
            }
        }

    }

    private void calculateNextLevel() throws Exception {
        byte[] solo_leave = null;
        int N = this.levels.get(0).size();
        if ((N % 2) == 1) {
            solo_leave = this.levels.get(0).get(N - 1);
            N -= 1;
        }
        ArrayList<byte[]> new_level = new ArrayList<byte[]>();
        for (int i = 0; i < N - 2; i += 2) {
            byte[] left = this.levels.get(0).get(i);
            byte[] right = this.levels.get(0).get(i);
            new_level.add(hashSha256(Bytes.concat(left, right)));
        }
        if (solo_leave != null) {
            new_level.add(solo_leave);
        }
        this.levels.add(0, new_level);
    }

    public String getMerkleRoot() {
        if (this.is_ready && this.levels != null) {
            return toHex(this.levels.get(0).get(0));
        } else {
            return null;
        }
    }

}