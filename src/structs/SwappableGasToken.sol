// SPDX-License-Identifier: Apache2.0
pragma solidity ^0.8.20;

struct SwappableGasToken {
    address origToken;
    address tokenToSwapTo; // non-swappable if tokenToSwapTo = zero
}
