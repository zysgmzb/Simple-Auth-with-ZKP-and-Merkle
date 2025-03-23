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
        vk.alpha = Pairing.G1Point(uint256(0x305c81fdfb5cc50d58820434caf9a1cc5e488cdaf467490d45078d5316a0a2ae), uint256(0x1f17f0bd4291ac5871811ba7852004bc21280b5ec5647dda0c08a4c84d255221));
        vk.beta = Pairing.G2Point([uint256(0x0783499b1ad154070519f5206895c0b9f834b4c95a6bdf9dff68c2712647ea96), uint256(0x1f96b800c2d370f3ec66182df537a67ec6a25e620253ca2079bc1db53c8e45b7)], [uint256(0x151b4dc3841d79759e9ffea1c25ce1e0cea02b97d48679eee575d87ec46cc48b), uint256(0x0b49f68a225e4fd9927b18a92ac89981d633da5fce87537949f6151ded082b77)]);
        vk.gamma = Pairing.G2Point([uint256(0x18fe61bfb4b151220287205a5f8a762eb80dd3eb5ef18bc0f42a11bf45360f5b), uint256(0x24abc38c6713791705b99c577ad3b02e65deb702593c0c5c1b3d0ad06f08310b)], [uint256(0x23674e7f023c2a0ae2177acde9d2963104db04227bd3ddc259d81173e11dd67a), uint256(0x1388a55c27e4afa602cc46bd14d9958cfba48327b569dedf368a00a693bda9d2)]);
        vk.delta = Pairing.G2Point([uint256(0x1e801645ec20cde66a01b2bf914919295a99d92cd99f4e4e3761b9340669f4ce), uint256(0x0fffb24a4b0bb5f441bc12409de650b652b7f4d4df28183b19899214161fe655)], [uint256(0x23e766e7f051bef61a5620243748d5baa720b46b2cc4c9a062439075e7cf5302), uint256(0x15f2bbaf10b118b844a6291352c60927f7cb9d42cc876fdc2bfa8e6b8e7bdd73)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x03163c9044c20f8b56433a237aaf206dda518d8925c1c5da0e3e9794d615430b), uint256(0x2918830a44d16e1807b3ce637aaafd2bed46e9134f062b35eba735f3ce90f355));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1507a1e7a3d279fdeba9591e4fa8cf327de1291e094364c0dfd2d7d4ebdc87f0), uint256(0x26d99fc49e0aba5579d11673946235c080881afc00fc3bf6c9f7bd1585f353d0));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0956b65c1e56766f9b19dfaa3325d4df30f3f005b48bd379380695238431caba), uint256(0x2d0cad645066e9b4a4c0a9613e43acf81b131b44a78b3b1bc482c604ed91c951));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x10590a2ca60e993cbc09cbd1a723a1487d1243ebcd3c68b4d8d9f8641c9470fe), uint256(0x1af7c4590f286759a537ff0bde9d117dc224ac28ff16faa5d15c636802c2d8ab));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1234a767a9385aea5e1248e91982900710166ce82790a062036a249deeff870e), uint256(0x04440aa6e76a43f40c09c15af8b643bc6f7197e7bd2dda906c59ace8fce78a84));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0b66ec155936bbf811e61b653475e621eab140d20260573ba479cc8c944ec8e7), uint256(0x03cd4f9b6d2fa738d52364040db4da1f1929ed618bf7ad33e06504127eeaf84e));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x157f5019671d640569b475dc07e5a5f9e420a5fa66e1eb62ae27530d753ae6b3), uint256(0x21c547fee96ddb77eaf71eb5bfeba325d2081c818364ed1b12b45916e6e65647));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x238b3b8ad63d55cd6593b8e3901506a095e7233aef842ecc71c692587726cdbb), uint256(0x27ffcd614f2a8c71976028398d9ec2d3408fbaf4ba54d93e27717f7df4b54f46));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x02403e998952d1641f1bd0ac06e1c67d1482aaf13e8132e54b427649e673c412), uint256(0x01eef720ac34516a22f430f6d5540cc87b2edf5399d95c94ac81e9231bcacf57));
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
