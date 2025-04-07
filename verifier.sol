// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x2c267632379d51375a926ba4d1653a11fa4cc21d34b583f0ae7dbd7d9ce6b9e3), uint256(0x06313c050834ba36b6f31f5855336a11bb9379a4628e25fc6866880eea7925d1));
        vk.beta = Pairing.G2Point([uint256(0x0971cf8c88aded8710b8c3f11bf36be06c29faa0f1a6c34d87809c49f6cf49df), uint256(0x046d6124d8f74ccf84584a540be76d5de57a649912c95ac1b3e8a58dc5aa8ae0)], [uint256(0x227045c9f1e73f4779709181fa91a924f0e49139032d35206df2d941944cadf7), uint256(0x0b3783543bf16127030ab7a5c1740190242525720abb5a246bbf30df82ced987)]);
        vk.gamma = Pairing.G2Point([uint256(0x251d4adac433b1fb3531c740b7e46c1256f1f9aa090dae7d9219e55ea2799412), uint256(0x097a136a3101f1e5294666ad4231a96e95906125d586358cf604f51fa89b187c)], [uint256(0x1ae8f460ba14cd36813672d5b497032132ecc83ba7d59359ed02e5db76011c12), uint256(0x144db64636f7664f4f4f5daa4c75622e9d783e62bdfaec8018be588e6472dec1)]);
        vk.delta = Pairing.G2Point([uint256(0x2b3a0e5ba24b6280cc15bb6351e5e740041a4b7a980084425beacd9fd9ae8562), uint256(0x15477ffcd766b3ad60b4ed159fc72d8ae74814d92c21461b0f5ab5d43fa7a740)], [uint256(0x042b2e924f0df543ae28a7b2fc936b37ea428e2165159124294ad10644f66b71), uint256(0x286acecc1c6b691d3ec3a206ef7a35ed65325f8af6d03973bbab8e158569e49a)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x28c1e5f9259360c25e08852b61cdbc4a920471c036a21c44dd7a523735b6a0b5), uint256(0x080de2f5740aee585b7dba610c8bbf1989cdc2e852c6fe11daf7ca0522f19971));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2ce23188577ef2cf315fa37724ef4583addcd51fb3499e114e9443531cd2a29f), uint256(0x2bdd3560a61d012c79ea37e8531dca5e15df74b51e43c33fda8e271e0cca3061));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x227acf95eea70ba9e219508a89784e0fa40dac1588c3f336e14088571ac36711), uint256(0x066962214001783c20e31107b0db92ac89588735aa04ed70b48aa77e568dd5fc));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x30487fbb47ef4bb6593c76a0f037470577f547c9628d7bb356c3265739098f6c), uint256(0x022421192b53caeea3dcc91b83eb3dc1c7d12e1fa5af1d3e9e8aedf6995c97e6));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x14d05d3aa48e01a4a935afad001009db224562703a81bedff84fc1171bd355e0), uint256(0x2a6487759e03d01d06ed7a2bbf06d77000371b604cac604c8c6e9bdc6c2b4d2a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x19b9d37a53bd09a5113fe3f1b0b0a0b4dc15267632c0f4aea9d576516b20b302), uint256(0x0c09347fcfda7bb4ebb68f1159424a216b73fc6ee173af15e003233240a72bd8));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0068554782e2342c95f113eb7b42791956c9696f4274ca0b59857e5e4257cee1), uint256(0x1b162a2eff99b071a0383abe1d9e071e84be14be71840c28f0fd5e0a7d14d822));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0771957bfd6a5bda6d9ae3e7dde44307482364d95a97c389434318f47d831072), uint256(0x1958f14f5ce101c5fa947611b777215e5e18c7d537050e46cb518b2a268a4181));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0ae08262e02256be398e5efd67e40cdf5e8121bef8c3c700d91d0451d8057af2), uint256(0x1485dddb454042c48ab428b1a7e270d6db680afa2f48b4f6bd7e259a6937932a));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[8] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](8);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
