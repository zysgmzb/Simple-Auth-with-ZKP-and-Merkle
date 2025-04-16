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
        vk.alpha = Pairing.G1Point(uint256(0x0c794e79026c4a16d484fb5579ec54004641b3c09333acfa6a58f1732ca6e168), uint256(0x163ea857d64dc30d05efa6c9000b10d649337bb0483c5f17d54004df9aabe524));
        vk.beta = Pairing.G2Point([uint256(0x302e1f7b96ae9e0621cb2a927cfe8ca1e2bbca6b2c44c87cc896cdfd1ab76834), uint256(0x28e1f801401ffbb4d36ed795870725a3361f7c7363f87290342bfa04cafda5aa)], [uint256(0x11274be69164240ca83a3ff8b986feab0d0e28da8efdac7ea28cd052f6695fe5), uint256(0x299d64c7eed8a0fd7bfbbaceec7b70819b6555baabc205137b9b7f3eacffd088)]);
        vk.gamma = Pairing.G2Point([uint256(0x28dc59a19c5a4a0fa801d3872c45a1e2bfd90aac30118f99bbb6a8999e762a25), uint256(0x2c872999aed256beac1e298d15f4239a2b807ece337c496f8343421b89e4373e)], [uint256(0x17fa63e597ce538ea5e1197c38598a5e9fb2539c854bbabe8a9fc8a98580b9d5), uint256(0x0bd1c2aee7c510d331d80cb0930a625da96c764bdae81a29262226597f957128)]);
        vk.delta = Pairing.G2Point([uint256(0x0d56d4cc1c24d4afda6100e67ba6caa80daadf71120ad693960fd9daffe36262), uint256(0x06221b2b48dfa02326a421388a65bebb4c805955a8c5226ed174074c2a09262e)], [uint256(0x26bd1c9fad5c5b247011b8b8814930b05cf6a0f69f3c9feda48118d16adcc780), uint256(0x13ac6452e299a3b486379a6661e7e4b0725d19a5dee83f74bd9d99f61de6a6ca)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x10f0e1415b8d3d958b92e864a93958148ad202a93238c6fc9984431b30738b3c), uint256(0x2cab9c43c61c7d2b60af5d859a75ea8ca2096220f23e71848e782ad6a3443720));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2d16b2550d0086ee3b445a38cc8405a1e7d411127661a5d935c4761347f3bd4c), uint256(0x04b6628130217fd259d34c317717d7f35e71dfb0d346918aa3d3ca4062d0450e));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x05e167fe3a5c84ed166f80c4a3a77dc310a6ce6aa27aa9eab0216b8bc86c7881), uint256(0x10107d5351adb1fd080944cd6ca0ef768ed7822abd1dc7342f9ac0cf578addc1));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x203b3f524e984b6f2bd4c05dc2811457516816bfa024ef800d0c7dd20c9d1b4d), uint256(0x210f567ac84b741ee178da04dabb94363542923ce95eefcc84e7eaf8f80643af));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1633cc0e3fc5dc7d2f889608ef4be6b11231a5535caa60fa14871adc7bd69cba), uint256(0x2d709dbfa920982c22001e44555d20f3ecf454b09b455bbd9347d94e1bbc4892));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2c1085541f5e0d52727e3cda97236b4c67a2b6deb3201258fbaa99b2a4a80694), uint256(0x1819b2198ed127596be5faccdf2bd8b89d2893dfc1b7fb2bd9d2ff94b9202620));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x191813181061803ba0f4d63141d794747bae5e3e4129a72541f3eef93308bf9f), uint256(0x0a86a638f8af32b05779877c76b75cf8c405818283de84e7701146edeab20d16));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1093e970134e6ca7835b5e5f2f245bb5797dc2d29d70c5aa51f50751c1dfd005), uint256(0x005761ab187b486ed8d6c273431400342c9b01569dd7175793af95e756b58b2c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1b0ff15a9aa1a93fc33259357ef8be5d8d1398a719eaa711c8700728d994f616), uint256(0x29ea601b4facab3a614e0cbddd6ab58762511833e54bd61cfd3852bacd3012cb));
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
