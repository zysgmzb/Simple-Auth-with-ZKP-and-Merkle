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
        vk.alpha = Pairing.G1Point(uint256(0x11b06fbb55f403d14ae187e2ab11f6c0417dd090d49b3ed148cb3e67146bc92e), uint256(0x0b9abe07698829d340118aa8320d887f39070605b1f748523a9ba34f86d7c55b));
        vk.beta = Pairing.G2Point([uint256(0x094befe44ecaf28d033f0956577bd2e470f2b29f58c816c3c56d5165bb86c237), uint256(0x1387df26c1bdfa8ece44867c20528ce7a4107637ef355372f4de273ce190862f)], [uint256(0x1921f559abe36ae4b00316e5789a7f5d21d85cafbe6ca010ae43f2faf30dc419), uint256(0x091412c9e1b9a1f53a0ca04b08f1d08516f9b840615d255fcb13cd4770631346)]);
        vk.gamma = Pairing.G2Point([uint256(0x24bf032a7ee3b0bab6c3a9b7a9f0224fa737bee45bd39539b67f8d07af11a9b1), uint256(0x2a4ba291fc526bdfffade0a178d21fbf4bdfbeaf88d577c8675479c4491edda7)], [uint256(0x19ebe516a7b2d4bb1bf326106e5c2d80c147f0fd527eda054ca6a8eebd919945), uint256(0x0c843208f43496a483d02136b74651d57c2e70c3f2eff67fe3edf7fec0cd20c2)]);
        vk.delta = Pairing.G2Point([uint256(0x0b6d13e2b28485abeadc2e9346cec607310bb9792984c7b06d218b7e506dfae4), uint256(0x048f820867210480fd3e50fd2ccf24746e74ece338b6729857ff86a112707b91)], [uint256(0x26869c088f629597a543b81ee2eec3c8352aa6a893ecc54fc6f51c406079c975), uint256(0x1fd930e2f43aa4bd601734245bc430372871a4ca8ac71824e68ad8b6a1176e47)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x01d5a7257c22b36628ff51242f928ba9d85620ae454bd6cd7f9c62b0d6601cad), uint256(0x17be113b07bc31d3e10b00059e6c204529269e6b1706c1352f0515748c80d281));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2fadd3fc7487b2969351b5ee0210fd62e7ecc2078aac90e6f19282fc059792f5), uint256(0x02cccf05ea0099794e1e21a60397a5e1cec0cdea1562b18065d2a40ca18411d4));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2949445518eefb0925a62df98b02e0ad3a6d550949ee3d653a7fc12ad1bd87ad), uint256(0x23cf87f76f6c086a5833c834103129fef2708c0d8bdf7e0b54e57294a1625ee1));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0e0f1b2faa5924fe4924c96c8450bad844bd9e5ddac71ff7ca3ccae538a2907d), uint256(0x22d8d50391ecdcdbcbea6ca4a2566efc3ab6139455d2540d68af194cfb5931cc));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0e334700cc5614b69c882f4b21d0d349fc053868cbba7368c0a865c721402e0f), uint256(0x0e01753cc9a49cf3f52f254045d6d9fed253c86329f1441049765740e7a7f91a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x15ff6aeb2580e40695672182c0ef15ec94f2c94edf8cc62c4ccdbea911e50726), uint256(0x19042e1818cc406fdc6e1df8a230bba61789a7d010727d91242ced7aa05ad46f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1c41d8e45702ee9abd56c722c83afc1c32dbd102a4be2dec679fef5a4aba0006), uint256(0x23a4a328731df789f9cf216f7a7e61d01382c813e513f197d4c10c47177a402b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0f6fca6a3e64aa48a00f6bf7a1f8093beb3730e4c61d30569539732bda2bd50c), uint256(0x0f98becaf99246eb428af266a196898cd8d9db1665b45489dbbc6a80448dc589));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x04d58f7077b2d23b1aa5c6c87ee1de89d21c8224e785fe28d32c3f4871e0a4c0), uint256(0x29d768a14cc820c0d9ff856b3def86b4a8e70e543523a46382cdcffa539424cb));
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
