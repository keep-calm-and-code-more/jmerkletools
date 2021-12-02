package jmerkletools;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;

import javax.xml.bind.DatatypeConverter;

import com.google.common.primitives.Bytes;

public class MerkleTools {
    private List<byte[]> leaves;
    private List<List<byte[]>> levels;
    public Boolean is_ready;

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

    public void addLeafHashedByte(List<byte[]> values) {
        this.is_ready = false;
        this.leaves.addAll(values);
    }



    private void addLeafString(List<String> values, Boolean do_hash) throws Exception {
        this.is_ready = false;
        for (String v_raw : values) {
            byte[] v_bytes;
            if (do_hash) {
                v_bytes = hashSha256(v_raw);
            } else {
                String v_hex = v_raw; // 如果v_raw已经是哈希后的字符串（16进制形式）
                v_bytes = hex2Bytes(v_hex);
            }
            this.leaves.add(v_bytes);
        }
    }
    public void addLeafAnyString(List<String> values) throws Exception{
        this.addLeafString(values, true);
    }

    public void addLeafHexString(List<String> values) throws Exception {
        this.addLeafString(values, false);
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
        this.is_ready = true;

    }

    private void calculateNextLevel() throws Exception {
        byte[] solo_leave = null;
        int N = this.levels.get(0).size();
        if ((N % 2) == 1) {
            solo_leave = this.levels.get(0).get(N - 1);
            N -= 1;
        }
        ArrayList<byte[]> new_level = new ArrayList<byte[]>();
        for (int i = 0; i < N - 1; i += 2) {
            byte[] left = this.levels.get(0).get(i);
            byte[] right = this.levels.get(0).get(i+1);
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

    public ArrayList<HashMap<String, String>> getProof(int index) {
        if (this.levels == null || index < 0 || index > this.leaves.size() - 1 || this.is_ready == false) {
            return null;
        } else {
            ArrayList<HashMap<String, String>> proof = new ArrayList<HashMap<String, String>>();
            for (int x = this.levels.size() - 1; x > 0; x--) {
                int level_len = this.levels.get(x).size();
                if (index == level_len - 1 && level_len % 2 == 1) {
                    index = index / 2;
                    continue;
                }
                Boolean is_right_node = (index % 2) != 0;
                int sibling_index = is_right_node ? index - 1 : index + 1;
                String sibling_pos = is_right_node ? "left" : "right";
                String sibling_value = toHex(this.levels.get(x).get(sibling_index));
                HashMap<String, String> map = new HashMap<>();
                map.put(sibling_pos, sibling_value);
                proof.add(map);
                index = index / 2;
            }
            return proof;
        }
    }

    public Boolean validateProof(ArrayList<HashMap<String, String>> proof, String target_hash, String merkle_root)
            throws Exception {
        return this.validateProof(proof, hex2Bytes(target_hash), hex2Bytes(merkle_root));
    }

    public Boolean validateProof(ArrayList<HashMap<String, String>> proof, byte[] target_hash, byte[] merkle_root)
            throws Exception {
        if (proof.size() == 0) {
            return target_hash == merkle_root;
        }
        byte[] proof_hash = target_hash;
        for (HashMap<String, String> p : proof) {
            String left = p.get("left");
            if (left != null) {
                byte[] sibling = hex2Bytes(left);
                proof_hash = hashSha256(Bytes.concat(sibling, proof_hash));
            } else {
                byte[] sibling = hex2Bytes(p.get("right"));
                proof_hash = hashSha256(Bytes.concat(proof_hash, sibling));
            }
        }
        return Arrays.equals(proof_hash,merkle_root);
    }
    public void printTree(){
        ListIterator<List<byte[]>> it = this.levels.listIterator();
        while(it.hasNext()){
            System.out.println(it.nextIndex());
            List<byte[]> one_level = it.next();
            for(var element :one_level){
                System.out.println("\t"+ bytes2Hex(element));
            }
            
        }
    }
}
