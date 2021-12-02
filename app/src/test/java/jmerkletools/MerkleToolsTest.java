package jmerkletools;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.UUID;

public class MerkleToolsTest {
    private static ArrayList<byte[]> values = new ArrayList<byte[]>();
    @BeforeClass
    public static void prepare() throws Exception{
        for (int i = 0; i < 2000; i++) {
            values.add(MerkleTools.hashSha256(UUID.randomUUID().toString().replace("-", "")));
        }
    }
    @Test
    public void testAddLeaf() throws Exception {
      
        long startTime = System.currentTimeMillis();
        MerkleTools mt = new MerkleTools();
        mt.addLeafHashedByte(values);
        mt.makeTree();
        long estimatedTime = System.currentTimeMillis() - startTime;
        System.out.println("wtf??");
        System.out.println(estimatedTime);
        assertTrue(mt.is_ready);
        assertEquals(mt.getLeafCount(), 2000);
    }
    @Test
    public void testGetProof() throws Exception{
        MerkleTools mt = new MerkleTools();
        ArrayList<String> vl = new ArrayList<String>();
        vl.add("some string");
        vl.add("some other string");
        var target_hash = MerkleTools.bytes2Hex(MerkleTools.hashSha256("some string"));
        System.out.println("\ttarget:"+target_hash);
        mt.addLeafAnyString(vl);
        mt.makeTree();
        var proof = mt.getProof(0);
        System.out.println("proof:"+proof);
        var merkle_root = mt.getMerkleRoot();
        System.out.println("merkle root:"+merkle_root);
        mt.printTree();
        mt.validateProof(proof, target_hash, merkle_root);
        assertTrue(mt.validateProof(proof, target_hash, merkle_root));
    }
}
