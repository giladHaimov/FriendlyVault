// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {FriendlyVault} from "../src/FriendlyVault.sol";

contract FriendlyVaultTest is Test {
    FriendlyVault public vault;

    function setUp() public {
        vault = new FriendlyVault();
    }
}
