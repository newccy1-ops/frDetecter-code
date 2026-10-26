package frdetecter;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import com.google.gson.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

/** Same bounded single-batch relation as the existing backend, in real jsnark.
 * Private witness hints are ALL checked by equations and range constraints.
 * Server build mode never reads the private input or actual MNIST data.
 */
public class BatchCircuit extends CircuitGenerator {
    static final BigInteger Q = BigInteger.ONE.shiftLeft(30);
    static final BigInteger P = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    static final int[] PARTIAL = {56,57,56,60,60,63,64,63,60,66,60,65,70,60,64,68};
    final JsonObject spec, constants;
    final Path witnessPath;
    Wire[] pub, labels, submitted;
    Wire[][] pixels;
    Wire salt;
    final Map<Integer, BigInteger[]> roundConstants = new HashMap<>(), sparseConstants = new HashMap<>();
    final Map<Integer, BigInteger[][]> mds = new HashMap<>(), preSparse = new HashMap<>();

    public BatchCircuit(JsonObject spec, JsonObject constants, Path witnessPath) {
        super("batch_sgd"); this.spec=spec; this.constants=constants; this.witnessPath=witnessPath;
        if (!Config.FIELD_PRIME.equals(P)) throw new IllegalArgumentException("Field mismatch");
    }
    static JsonObject read(Path file) throws Exception {return JsonParser.parseString(Files.readString(file)).getAsJsonObject();}
    static BigInteger integer(JsonElement e) {
        String s=e.getAsString(); return s.startsWith("0x") ? new BigInteger(s.substring(2),16) : new BigInteger(s);
    }
    static BigInteger signed(BigInteger n) {return n.compareTo(P.shiftRight(1))>0 ? n.subtract(P):n;}
    static BigInteger floor(BigInteger n, BigInteger d) {
        BigInteger[] qr=n.divideAndRemainder(d); return qr[1].signum()<0 ? qr[0].subtract(BigInteger.ONE):qr[0];
    }
    Wire sum(Wire[] ws) {return new WireArray(ws).sumAllElements();}
    Wire pow5(Wire a) {Wire s=a.mul(a);return s.mul(s).mul(a);}
    BigInteger[] vector(JsonArray a) {BigInteger[] out=new BigInteger[a.size()];for(int i=0;i<out.length;i++)out[i]=integer(a.get(i));return out;}
    BigInteger[][] matrix(JsonArray a) {BigInteger[][] out=new BigInteger[a.size()][];for(int i=0;i<out.length;i++)out[i]=vector(a.get(i).getAsJsonArray());return out;}
    Wire[] mix(Wire[] s, BigInteger[][] a) {
        Wire[] out=new Wire[s.length];
        for(int i=0;i<s.length;i++){Wire[] terms=new Wire[s.length];for(int j=0;j<s.length;j++)terms[j]=s[j].mul(a[j][i]);out[i]=sum(terms);}
        return out;
    }
    // circomlibjs optimized Poseidon schedule, identical field/hash parameters.
    Wire poseidon(Wire... inputs) {
        int t=inputs.length+1, index=t-2, np=PARTIAL[index];
        if(!roundConstants.containsKey(t)) {
            roundConstants.put(t,vector(constants.getAsJsonArray("C").get(index).getAsJsonArray()));
            sparseConstants.put(t,vector(constants.getAsJsonArray("S").get(index).getAsJsonArray()));
            mds.put(t,matrix(constants.getAsJsonArray("M").get(index).getAsJsonArray()));
            preSparse.put(t,matrix(constants.getAsJsonArray("P").get(index).getAsJsonArray()));
        }
        BigInteger[] c=roundConstants.get(t), sparse=sparseConstants.get(t);
        Wire[] s=new Wire[t];s[0]=getZeroWire();System.arraycopy(inputs,0,s,1,inputs.length);
        for(int i=0;i<t;i++)s[i]=s[i].add(c[i]);
        for(int r=0;r<3;r++){for(int i=0;i<t;i++)s[i]=pow5(s[i]).add(c[(r+1)*t+i]);s=mix(s,mds.get(t));}
        for(int i=0;i<t;i++)s[i]=pow5(s[i]).add(c[4*t+i]);
        s=mix(s,preSparse.get(t));
        for(int r=0;r<np;r++){
            s[0]=pow5(s[0]).add(c[5*t+r]);
            Wire[] terms=new Wire[t];for(int j=0;j<t;j++)terms[j]=s[j].mul(sparse[(2*t-1)*r+j]);
            Wire first=sum(terms);
            for(int k=1;k<t;k++)s[k]=s[k].add(s[0].mul(sparse[(2*t-1)*r+t+k-1]));
            s[0]=first;
        }
        for(int r=0;r<3;r++){for(int i=0;i<t;i++)s[i]=pow5(s[i]).add(c[5*t+np+r*t+i]);s=mix(s,mds.get(t));}
        for(int i=0;i<t;i++)s[i]=pow5(s[i]);
        return mix(s,mds.get(t))[0];
    }
    Wire commit(Wire[] values, int domain, Wire privateSalt) {
        Wire state=poseidon(createConstantWire(domain),createConstantWire(values.length),privateSalt);
        for(int i=0;i<values.length;i+=15){Wire[] block=new Wire[16];block[0]=state;for(int j=0;j<15;j++)block[j+1]=i+j<values.length?values[i+j]:getZeroWire();state=poseidon(block);}
        return state;
    }
    Wire[] pack(Wire[] values,int width,int count) {
        Wire[] out=new Wire[(values.length+count-1)/count];
        for(int i=0;i<out.length;i++){List<Wire> terms=new ArrayList<>();for(int j=0;j<count&&i*count+j<values.length;j++)terms.add(values[i*count+j].mul(BigInteger.ONE.shiftLeft(width*j)));out[i]=sum(terms.toArray(new Wire[0]));}
        return out;
    }
    Wire divide(final Wire a, final BigInteger d, int qBits, int rBits) {
        final Wire q=createProverWitnessWire("floor quotient"),r=createProverWitnessWire("floor remainder");
        specifyProverWitnessComputation(e->{BigInteger av=signed(e.getWireValue(a));BigInteger qv=floor(av,d);e.setWireValue(q,qv.mod(P));e.setWireValue(r,av.subtract(qv.multiply(d)));});
        addEqualityAssertion(a,q.mul(d).add(r));
        q.add(BigInteger.ONE.shiftLeft(qBits)).restrictBitLength(qBits+1);
        r.restrictBitLength(rBits);
        if(!d.equals(BigInteger.ONE.shiftLeft(rBits)))addOneAssertion(r.isLessThan(d,rBits));
        return q;
    }
    Wire expNegative(Wire x) {
        long[] coefficients={1073741824L,1073741824L,536870912L,178956971L,44739243L,8947849L,1491308L};
        Wire t=divide(x,BigInteger.valueOf(32),31,5),z=createConstantWire(coefficients[6]);
        for(int k=5;k>=0;k--)z=divide(z.mul(t),Q,30,30).add(coefficients[k]);
        for(int k=0;k<5;k++)z=divide(z.mul(z),Q,31,30);
        z.restrictBitLength(31);return z;
    }
    Wire probability(final Wire e, final Wire total) {
        final Wire p=createProverWitnessWire("probability"),r=createProverWitnessWire("probability remainder");
        specifyProverWitnessComputation(ev->{BigInteger den=ev.getWireValue(total);if(den.signum()==0)throw new IllegalArgumentException("Zero probability denominator");BigInteger[] qr=ev.getWireValue(e).multiply(Q).divideAndRemainder(den);ev.setWireValue(p,qr[0]);ev.setWireValue(r,qr[1]);});
        addEqualityAssertion(e.mul(Q),p.mul(total).add(r));
        p.restrictBitLength(31);r.restrictBitLength(35);addOneAssertion(r.isLessThan(total,35));return p;
    }
    @Override protected void buildCircuit() {
        pub=createInputWireArray(4,"nonce,I,updateCommitment,contextTag");
        pixels=new Wire[64][];for(int n=0;n<64;n++)pixels[n]=createProverWitnessWireArray(784,"pixels");
        labels=createProverWitnessWireArray(64,"labels");submitted=createProverWitnessWireArray(7850,"submitted");salt=createProverWitnessWire("salt");
        salt.restrictBitLength(128);pub[0].restrictBitLength(128);
        Wire context=poseidon(createConstantWire(integer(spec.get("model_tag"))),createConstantWire(integer(spec.get("session_tag"))),createConstantWire(integer(spec.get("manifest_tag"))),getZeroWire(),pub[0]);
        addEqualityAssertion(context,pub[3]);
        Wire[] raw=new Wire[50240];
        Wire[][] eq=new Wire[64][10];
        for(int n=0;n<64;n++){
            for(int j=0;j<784;j++){pixels[n][j].restrictBitLength(8);raw[n*784+j]=pixels[n][j];}
            labels[n].restrictBitLength(4);addOneAssertion(labels[n].isLessThan(10,4));raw[50176+n]=labels[n];
            for(int k=0;k<10;k++)eq[n][k]=labels[n].isEqualTo(k);
        }
        addEqualityAssertion(commit(pack(raw,8,30),1,salt),pub[1]);
        Wire[] encoded=new Wire[7850];
        for(int i=0;i<7850;i++){encoded[i]=submitted[i].add(BigInteger.ONE.shiftLeft(25));encoded[i].restrictBitLength(26);}
        addEqualityAssertion(commit(pack(encoded,26,8),2,getZeroWire()),pub[2]);
        BigInteger[][] weights=matrix(spec.getAsJsonArray("weights_q"));BigInteger[] bias=vector(spec.getAsJsonArray("bias_q"));
        Wire[][] residual=new Wire[64][10];
        for(int n=0;n<64;n++){
            Wire[] logits=new Wire[10];
            for(int k=0;k<10;k++){
                Wire[] terms=new Wire[785];terms[0]=createConstantWire(bias[k].multiply(BigInteger.valueOf(255)));
                for(int j=0;j<784;j++)terms[j+1]=pixels[n][j].mul(weights[k][j]);
                logits[k]=divide(sum(terms),BigInteger.valueOf(255),34,8);
            }
            Wire maximum=logits[0];
            for(int k=1;k<10;k++){Wire lt=maximum.add(BigInteger.ONE.shiftLeft(34)).isLessThan(logits[k].add(BigInteger.ONE.shiftLeft(34)),35);maximum=maximum.add(lt.mul(logits[k].sub(maximum)));}
            Wire[] ex=new Wire[10];for(int k=0;k<10;k++)ex[k]=expNegative(logits[k].sub(maximum));Wire total=sum(ex);
            for(int k=0;k<10;k++)residual[n][k]=probability(ex[k],total).sub(eq[n][k].mul(Q));
        }
        for(int k=0;k<10;k++){
            for(int j=0;j<784;j++){
                Wire[] products=new Wire[64];for(int n=0;n<64;n++)products[n]=residual[n][k].mul(pixels[n][j]);
                sum(products).sub(submitted[784*k+j].mul(163200)).add(Q).restrictBitLength(31);
            }
            Wire[] column=new Wire[64];for(int n=0;n<64;n++)column[n]=residual[n][k];
            sum(column).sub(submitted[7840+k].mul(640)).add(BigInteger.ONE.shiftLeft(22)).restrictBitLength(23);
        }
    }
    @Override public void generateSampleInput(CircuitEvaluator e) {
        try {
            JsonObject in=read(witnessPath);
            String[] names={"nonce","dataCommitment","updateCommitment","contextTag"};
            for(int i=0;i<4;i++)e.setWireValue(pub[i],integer(in.get(names[i])).mod(P));
            e.setWireValue(salt,integer(in.get("salt")).mod(P));
            for(int n=0;n<64;n++){
                JsonArray row=in.getAsJsonArray("pixels").get(n).getAsJsonArray();
                for(int j=0;j<784;j++)e.setWireValue(pixels[n][j],integer(row.get(j)));
                e.setWireValue(labels[n],integer(in.getAsJsonArray("labels").get(n)));
            }
            for(int i=0;i<7850;i++)e.setWireValue(submitted[i],integer(in.getAsJsonArray("submitted").get(i)).mod(P));
        } catch(Exception error){throw new IllegalArgumentException("Private input load failed",error);}
    }
    public static void main(String[] args) throws Exception {
        if(args.length<3)throw new IllegalArgumentException("build|witness spec.json constants.json [private_input.json]");
        Path input=args.length>3?Path.of(args[3]):null;
        BatchCircuit circuit=new BatchCircuit(read(Path.of(args[1])),read(Path.of(args[2])),input);
        circuit.generateCircuit();circuit.writeCircuitFile();
        if(args[0].equals("witness")){if(input==null)throw new IllegalArgumentException("Missing private input");circuit.evalCircuit();circuit.prepFiles();System.out.println("JSNARK_WITNESS_OK");}
        else if(!args[0].equals("build"))throw new IllegalArgumentException("Unknown action");
        System.out.println("JSNARK_CIRCUIT_OK constraints="+circuit.getNumOfConstraints()+" private_batch_read="+(input!=null));
    }
}
