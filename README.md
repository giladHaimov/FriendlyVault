## FriendlyVault

**A lightweight-account-abstraction implementation relying on protocol-level governance management.**


### Purpose

This Solidity code implements a smart contract called "FriendlyVault" that acts as a secure storage and transfer system for digital assets (tokens and Core, a native cryptocurrency).
It's designed to facilitate a 'lightweight-account-abstraction' solution aimed at allowing non-blockchain users with an entry-point into the blockchain.

The basic approach I have used here was to replace the highly-complex network-level account-abstraction support used by ERC4337 with an applicative (or protocol) -level support relying on a smart-ccontract level governance mechanism.

Though small, this module in fact packs much of a punch:
-   Allow address-less users to interact with the blockchain - no private keys, no mnemonics storage
-   Allow deletaged gas payments using an allowance mechanism which allows the delegate account to specify the max amount of Tx he's willing to gas-fund per each relying account
-   Allow gas-payment using ERC20 tokens
-   Support injection of ERC20 token's Core value by an approved oracle
-   Allow per-user restriction (say when they prove to be non-fair player) so that the may only extract their assets out of the vault
-   Allows for governance account management (in fact: governance assignee account)
-   Limits the amount of Core stored in each account (do not send us your family savings)
-   Provides a 'Gasdrop' counter (a concept I have adapted from Ahmed) where each new account is granted his first N Tx to be costless
-   Support injection of suspected-scammer account information from an approved oracle. These accounts will be added by multiplying the gas fees based on a global scammersGasFactor value
-   Allow batch-operations where multiple 'lightweight transactions' will be executed in a single batch

The main limitation of the module is the fact that it cannot provide introspection into the complexity model of each Tx hence is forced to use a constant per-Tx fee. It can be argued that 
using a batch-mode operation the impact of this limitation may be somewhat reduced, still it is there.


## Implementation


### User Management

-   Registers users with unique usernames.
-   Tracks user activity and timestamps.
-   Allows for recovery of lost credentials under certain conditions.
-   Can restrict users from receiving assets for compliance purposes.

### Asset Storage

-   Stores balances of Core and various tokens for each user
-   Maintains a list of supported token types

### Token Transfers

-   Enables secure transfer of Core and tokens between users within the vault
-   Supports transfers from external addresses into the vault


### Gas Payment System

-   Charges gas fees for transactions to cover computational costs
-   Accepts payment in Core or supported tokens
-   Adjusts gas costs based on user reputation and suspected scammer status


### Batch Operations

-   **Allows execution of multiple transactions in a single call for efficiency.**


### Important Functions

-   **registerUser**: Registers a new user with a username.
-   **transferCoreFromVault**: Transfers Core from one user to another or to an external address.
-   **transferCoreFromExternalAddress**: Transfers Core from an external address into a user's vault.
-   **transferToken**: Transfers tokens between users or to external addresses.
-   **performBatchOperations**: Executes multiple transactions in a single call.
-   **setTokenValueInCores**: Sets the value of a token in terms of Core, used for gas fee calculations.
-   **setGasFactor**: Adjusts the gas fee multiplier for suspected scammers.
-   **setMaxCorePerUser**: Sets a maximum Core balance allowed per user.
-   **setMinUsernameLength**: Sets the minimum length for usernames.
-   **setNumGasdropsForNewcomers**: Provides new users with free gasdrops for initial transactions.


### Governance and Security

Certain functions can only be called by designated governance or delegate addresses, ensuring controlled updates and operations.
Employs reentrancy guards to prevent potential vulnerabilities.
Additional Notes:

The code includes mechanisms for oracles to provide external information like token values and scammer detection, enhancing its functionality.
It utilizes a "gas fee account" to hold fees collected for future use.


### Deploy upgredeable contracts

[See: https://github.com/OpenZeppelin/openzeppelin-foundry-upgrades]


-   Execute:


```
forge install OpenZeppelin/openzeppelin-foundry-upgrades
forge install OpenZeppelin/openzeppelin-contracts-upgradeable
```

-   Add to remappings.txt:

```
@openzeppelin/contracts/=lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/
@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/contracts/
```

-   Import the library in your Foundry scripts or tests:

```
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
```

Then call functions from Upgrades.sol to run validations, deployments, or upgrades.