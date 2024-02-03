// SPDX-License-Identifier: Apache2.0
pragma solidity ^0.8.20;

import {SwappableGasToken} from './SwappableGasToken.sol';

struct GasParams {
    string gasPayerDelegate;
    bool gasPaymentStartsWithCore;
    SwappableGasToken[] gasTokens;
  }
