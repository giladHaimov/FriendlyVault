// SPDX-License-Identifier: Apache2.0
pragma solidity ^0.8.20;

import {GasParams} from './GasParams.sol';

struct TxRecord {
    string originName;
    string fromName;
    address fromAddress;
    string toName;
    address toAddress;
    bool allowShortCircuit;

    address token;
    uint amount;

    GasParams gparams;
}
