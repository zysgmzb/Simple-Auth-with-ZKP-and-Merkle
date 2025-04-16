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
        vk.alpha = Pairing.G1Point(uint256(0x0992d1e9a302f6eb3f640fa772782203bd6c31a486a38e91fc9058bdecfa5535), uint256(0x0d70bdb2a199b748b5c97f2b2211bd300e29a4b851c94d05bb555bb3cc9518e0));
        vk.beta = Pairing.G2Point([uint256(0x026b1a0d10ac658de3f992ea5c9928c6568bedcf42e25bac1ea39cff7d26dc12), uint256(0x0032310f5791743d68ff2773db55ff6d3c3c6bebd7b47768f76c4be3fef1dd8f)], [uint256(0x0d0848a31adfca42e07e49a8eaa0fb5f01d872e61f7b4a8a657a92e079799748), uint256(0x0556cb7c131012cb2e374af2ce634c9fc90ca280d08ca670a016291c310ac108)]);
        vk.gamma = Pairing.G2Point([uint256(0x2cd50a9a6570ff0f87a45f3252b5836dd190e3272a1541015c5fd5076106f57d), uint256(0x037e94e45a0f2813f68d140b796f0a04d8238c3b61dd7b75556e845e2aafbb59)], [uint256(0x22d90d96d6a6668baba438f6430a0ea6edec19d6a5cd912e0bcd46f022907d50), uint256(0x1e45f8974193d9ce19b9491961afb0e959a2d07d01afe67d475514c938c4a65d)]);
        vk.delta = Pairing.G2Point([uint256(0x06b2be31376547080eabf754b156ea27df44f79ae336f47fda7bb5edff7e8813), uint256(0x2338515b8f8f7ef26e36613bed001354e002203153c054213377f22358d0939c)], [uint256(0x2065e51f3606a17d6b83f68b916ee8f8bfbdddffd4a6664e89cf6990c92de439), uint256(0x080a13595fa74cc0b10ae668c870b00ef0021c8b1e62efd48271b5d29f83086b)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2afc89f41f67ecde5bcd0b1de7b14bd1f09984051db51dd2eedea4cd2c76da67), uint256(0x0cfbbd022c539283643953463d16b8fc144b8aa8ac19a1883fd18f6821078fea));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x057153536f0c657eba21db7518adf03c8008c4419818fac780d9d00225d6be66), uint256(0x0374f420a1e892aa249c5b7a02858982b519759e9757c7eb0cce3a6ccb6e8dd5));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x225f67031ad43d8e0db223036b8db61f98772902f231f7ccd5438861b3b9c921), uint256(0x0873a64c03560f8ca5d3994ceab19be1691b8b9b69ab47e43b35555425a29378));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1699d70df858b3dd112d1d9550aaae051f7b7ef2db0bdcf87b26abad46efcd58), uint256(0x2ee4ce1ec3ae15d4fb548ffd54333d2f518521f030ed42ecc0725589972d6f03));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0cf4bfd0020fd92c42df11137129606d46bdc730cb7213991cf0745e62567b4e), uint256(0x1200204c2b47f6d77822423c7b0237a4cd4369f7faeb758835a68973a02b6cde));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x24b5e7d1f0032a32da493d217c5b1b7f41fec6a6c554887f010c7b99fa204efe), uint256(0x13644b38fb93377f43f835a7e45fae225ed8c61deaf015c504bcc8b753394d05));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1ec8a993af7542e382b703f187dc883c15e15552c357766d67063b33a607fe7b), uint256(0x0849b9e8886ee81c434e9648b15f2f50b1531c931bf6b38c335eb7976eee36a5));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x214ae63553b9cb1041152ffefa608bae5e6d9242adccb5e6ce715e2796e47206), uint256(0x2702206c47659e7447f57a8df544da992ea507b941dabace171058e59e3a56b1));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x107015fae03cb5e150f83c80b8f87c0c4d634f8483b603513be2cc9b2e8f7c41), uint256(0x0343ec4c90c5062f7564eb37caa2aba4b6eaeb284559ad366904d6a647afdabc));
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
