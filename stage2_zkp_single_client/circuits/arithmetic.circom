pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// Exact Euclidean signed division by a positive compile-time constant.
// q and r are witness hints, but *all* equations and bounds are constrained.
template FloorDiv(D, QB, RB) {
    signal input a;
    signal output q;
    signal r;
    q <-- ((a + (1 << QB)*D) \ D) - (1 << QB);
    r <-- (a + (1 << QB)*D) % D;
    a === q*D + r;
    component qr = Num2Bits(QB + 1);
    qr.in <== q + (1 << QB);
    component rr = Num2Bits(RB);
    rr.in <== r;
    if (D != (1 << RB)) {
        component lt = LessThan(RB);
        lt.in[0] <== r;
        lt.in[1] <== D;
        lt.out === 1;
    }
}

// Fixed-point exp(x), x in [-32,0]: degree-6 Taylor at x/32,
// followed by five squarings. Every truncation is constrained.
template ExpNegative() {
    var Q = 1073741824;
    var C[7] = [1073741824,1073741824,536870912,178956971,44739243,8947849,1491308];
    signal input x;
    signal output out;
    // The caller proves x is a logit minus the correctly selected maximum,
    // with every logit bounded in [-16Q,16Q). Hence -32Q < x <= 0.
    component scale = FloorDiv(32, 31, 5);
    scale.a <== x;
    signal p[7];
    p[6] <== C[6];
    signal product[6];
    component d[6];
    for (var j=0; j<6; j++) {
        var k=5-j;
        product[j] <== p[k+1]*scale.q;
        d[j] = FloorDiv(Q, 30, 30);
        d[j].a <== product[j];
        p[k] <== C[k] + d[j].q;
    }
    signal sq[6];
    sq[0] <== p[0];
    signal sqprod[5];
    component sd[5];
    for (var j=0; j<5; j++) {
        sqprod[j] <== sq[j]*sq[j];
        sd[j] = FloorDiv(Q, 31, 30);
        sd[j].a <== sqprod[j];
        sq[j+1] <== sd[j].q;
    }
    out <== sq[5];
    component rng = Num2Bits(31);
    rng.in <== out;
}

template Probability() {
    var Q = 1073741824;
    signal input e;
    signal input total;
    signal output p;
    signal r;
    p <-- (e*Q) \ total;
    r <-- (e*Q) % total;
    e*Q === p*total+r;
    component pbits = Num2Bits(31);
    pbits.in <== p;
    // e < 2Q from ExpNegative's range; total is the sum of ten such e's.
    // total > 0 because at least one maximum-subtracted logit is zero, whose
    // constrained exp is exactly Q. All products remain below 2^67 << p_field.
    component rb = Num2Bits(35);
    rb.in <== r;
    component lt = LessThan(35);
    lt.in[0] <== r;
    lt.in[1] <== total;
    lt.out === 1;
}

// Rate 15 Poseidon chain. Domain-separated; includes a private salt for data.
template Commit(N, DOMAIN) {
    signal input values[N];
    signal input salt;
    signal output out;
    var blocks = (N+14) \ 15;
    component initial = Poseidon(3);
    initial.inputs[0] <== DOMAIN;
    initial.inputs[1] <== N;
    initial.inputs[2] <== salt;
    signal state[blocks+1];
    state[0] <== initial.out;
    component h[blocks];
    for (var i=0; i<blocks; i++) {
        h[i] = Poseidon(16);
        h[i].inputs[0] <== state[i];
        for (var j=0; j<15; j++) {
            if (15*i+j < N) { h[i].inputs[j+1] <== values[15*i+j]; }
            else { h[i].inputs[j+1] <== 0; }
        }
        state[i+1] <== h[i].out;
    }
    out <== state[blocks];
}
