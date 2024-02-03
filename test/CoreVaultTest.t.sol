// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CoreVault} from "../src/CoreVault.sol";

contract CoreVaultTest is Test {
    string private SAM = "user-sam";
    string private DAVE = "user-dave";
    string private JOE = "user-joe";
    string private NON_USER = "undefined-user";

    address private s_governance = makeAddr("governance");
    address private s_govDelegate = makeAddr("governance-delegate");
    CoreVault private s_coreVault;

    function setUp() public virtual {
        s_coreVault = new CoreVault();
        s_coreVault.initialize(s_governance, s_govDelegate, 4, address(0));
    }


    function test_basicTrasferOps() public { 

        address payer1 = makeAddr("payer1");
        
        vm.startPrank(s_govDelegate);
         s_coreVault.registerUser(SAM);
         s_coreVault.registerUser(DAVE);
         s_coreVault.registerUser(JOE);
        vm.stopPrank();

        assertTrue(s_coreVault.isActiveUser(SAM));
        assertTrue(s_coreVault.isActiveUser(DAVE));
        assertTrue(s_coreVault.isActiveUser(JOE));
        assertFalse(s_coreVault.isActiveUser(NON_USER));

        hoax(payer1, 2 ether);
        uint pre = s_coreVault.getCoreBalance(JOE);
        s_coreVault.transferCoreFromExternalAddress{ value: 1 ether }(JOE);
        uint post = s_coreVault.getCoreBalance(JOE);

        assertEq(post- pre, 1 ether, "transfer failed");

    }
} 