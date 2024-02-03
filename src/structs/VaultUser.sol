// SPDX-License-Identifier: Apache2.0
pragma solidity ^0.8.20;

struct VaultUser {
    uint lastActiveTime;
    uint numGasdropsLeft;
    bool isActiveUser;
    bool isSuspectedScammer;
}
