## FriendlyVault

**A lightweight-ERC4337 implementation relying on protocol-level account management.**


### Purpose

This Solidity code implements a smart contract called "FriendlyVault" that acts as a secure storage and transfer system for digital assets (tokens and Core, a native cryptocurrency).
It's designed to facilitate trustless transactions between users within a decentralized application (dApp).
Key Features:


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