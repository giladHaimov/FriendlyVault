// SPDX-License-Identifier: Apache2.0
pragma solidity ^0.8.20;

import "@oz_upgredeable/contracts/proxy/utils/Initializable.sol";
import "@oz_upgredeable/contracts/utils/ReentrancyGuardUpgradeable.sol";

interface IERC20 {
  function transfer(address to, uint256 value) external returns (bool);
  function transferFrom(address from, address to, uint256 value) external returns (bool);
  function allowance(address owner, address spender) external view returns (uint256);
}


contract FriendlyVault is Initializable, ReentrancyGuardUpgradeable {
  
  uint[32] public __gap; // sanity gap for future stateful base-contracts
  
  uint public constant DEF_LOST_CREDENTIALS_MIN_INACTIVITY_PERIOD = 10 weeks;
  uint public constant DEF_MIN_USERNAME_LEN = 4;
  uint public constant DEF_MAX_CORE_PER_USER = 4000e18;
  uint public constant DEF_FIXED_TX_GAS_FEE = 1e18/100;
  uint public constant DEF_SCAMMER_GAS_FACTOR_MILLICORE = 3*1000;  

  address public constant CORE = address(0x11);

  string public constant GAS_FEE_ACCOUNT = "gas_fee_account"; 

  address public s_governance; // GOV_HUB = 0x0000000000000000000000000000000000001006;

  uint public g_scammersGasFactorMilliCores = DEF_SCAMMER_GAS_FACTOR_MILLICORE;
  uint public s_fixedTxGasFee = DEF_FIXED_TX_GAS_FEE;
  uint public s_lostCredentialsInactivityPeriod = DEF_LOST_CREDENTIALS_MIN_INACTIVITY_PERIOD;
  uint public s_maxCorePerUser = DEF_MAX_CORE_PER_USER;
  uint public s_minUsernameLength = DEF_MIN_USERNAME_LEN;

  uint public s_numGasdropsForNewcomers; // assigned to each new user
  address public s_govDelegate;
  address public s_tokenValueOracle;
  address public s_scammerDetectorOracle;
  bool private s_disableGasPayments = false;
  
  mapping(string => mapping(address => uint)) public s_balances; // CORE included!
  mapping(string => VaultUser) public s_activeUsers;
  mapping(string => bool) public s_restrictedUsers; // if set - active user may not receive new assets

  address[] public s_tokenTypesInVault; // CORE excluded
  mapping(address => uint) public s_tokenTotals; // CORE excluded (its total can always be taken from contract's balance)
  mapping(address => uint) public s_tokenToCoreValues; 
  //------------


  event VaultInitialized(address _governance, address _govDelegate, uint _defaultNumGasdrops);

  event RegisterNewUser(string indexed username);

  event UnregisterUser(string indexed username);

  event RestrictUserForReceival(string indexed username, bool oldRestict, bool newRestict);

  event SetMinUsernameLength(uint oldLen, uint newLen);

  event SetNumGasdropsForNewcomers(uint oldNum, uint newNum);
  
  event SetScammerGasFactor(uint oldFactor, uint newFactor);

  event SetMaxCorePerUser(uint oldMax, uint newMax);

  event SetTokenValueOracle(address indexed oldAddress, address indexed newAddress);

  event SetScammerDetectorOracle(address indexed oldAddress, address indexed newAddress);

  event SetMinLostCredentialsInactivityPeriod(uint oldMin, uint newMin);

  event SetScammerStatus(string indexed username, bool oldSuspectedScammer, bool newSuspectedScammer);

  event SetFixedTxGasFee(uint oldFee, uint newFee);

  event RecoverLostCredentials(string indexed origUser, string indexed recoveredUser);

  event TokenRemovedFromInVaultArray(address indexed _token);

  event SetTokenValueInCores(address indexed token, uint oldVal, uint newVal);

  event SetGovDelegate(address indexed oldDelegate, address indexed newDelegate);

  event TransferCoreFromVault(string indexed originName, string indexed toName, address indexed toAddress, uint amount);

  event TransferCoreFromExternalAddress(string indexed originName, address indexed fromAddress, string indexed toName, uint amount);

  event TransferToken(string indexed originName, address fromAddress, string indexed fromName, string indexed toName, address toAddress, address token, uint amount);
  
  event BatchOperations(string indexed originName, uint numOps);
  //------------


  error CoreValueNotSetForToken(address token);

  error InvalidToken(address token);
  
  error NotAnActiveUser(string username);
  
  error InvalidUsername(string username);

  error UserAlreadyRegistered(string username, uint lastActiveTime);
  //------------


  struct GasParams {
    bool gasPaymentStartsWithCore;
    address[] gasTokens;
  }

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

  struct VaultUser {
    uint lastActiveTime;
    uint numGasdropsLeft;
    bool suspectedScammer;
  }

  struct BatchOperation {
    bytes data;
    uint value;
  }
  //------------


  modifier onlyGovernance() {
    require(msg.sender == s_governance, "op allowed only for governance contract");
    _;
  }

  modifier onlyGovDelegate() {
    require(msg.sender == s_govDelegate, "not gov delegate address");
    _;
  }

  modifier onlyTokenValueOracle() {
    require(msg.sender == s_tokenValueOracle, "not token value oracle");
    _;
  }  

  modifier onlyScammerDetectorOracle() {
    require(msg.sender == s_scammerDetectorOracle, "not scammer detector oracle");
    _;
  }    
  //------------


  receive() external payable { 
    revert("cannot pass Core to vault without specifying destination"); 
  }

  function initialize(address _gov, address _govDelegate, uint _defaultNumGasdrops) external initializer {
    __ReentrancyGuard_init();
    require(_gov != address(0), "missing governance addr");
    require(_govDelegate != address(0), "missing govDelegate addr");
    s_governance = _gov;
    s_govDelegate = _govDelegate;
    s_numGasdropsForNewcomers = _defaultNumGasdrops;
    _registerUser(GAS_FEE_ACCOUNT); // avoid malicious users from registering this username
    emit VaultInitialized(_gov, _govDelegate, _defaultNumGasdrops);
  }

  function registerUser(string memory username) external nonReentrant onlyGovDelegate {
    _registerUser(username);
    emit RegisterNewUser(username);
  }

  function numTokenTypesInVault() external view returns (uint) {
    return s_tokenTypesInVault.length;
  }

  function setScammerStatus(string memory username, bool newStatus) external onlyScammerDetectorOracle {
    _requireValidUsername(username);
    _requireActiveUser(username);
    bool oldStatus = s_activeUsers[username].suspectedScammer;
    s_activeUsers[username].suspectedScammer = newStatus;
    emit SetScammerStatus(username, oldStatus, newStatus);
  }

  function restrictUserForReceival(string memory username, bool restict) external nonReentrant onlyGovDelegate {
    _requireValidUsername(username);
    _requireActiveUser(username);
    bool oldRestictMode = s_restrictedUsers[username];
    s_restrictedUsers[username] = restict;
    emit RestrictUserForReceival(username, oldRestictMode, restict);
  }

  function setMinUsernameLength(uint newLen) external onlyGovDelegate {
    require(newLen > 1, "min username length too small");
    uint oldLen = s_minUsernameLength;
    s_minUsernameLength = newLen;
    emit SetMinUsernameLength(oldLen, newLen);
  }

  function setNumGasdropsForNewcomers(uint newNum) external onlyGovDelegate {
    uint oldNum = s_numGasdropsForNewcomers;
    s_numGasdropsForNewcomers = newNum;
    emit SetNumGasdropsForNewcomers(oldNum, newNum);
  }
  
  function setMaxCorePerUser(uint newMax) external onlyGovDelegate {
    uint oldMax = s_maxCorePerUser;
    s_maxCorePerUser = newMax;
    emit SetMaxCorePerUser(oldMax, newMax);
  }  

  function setTokenValueInCores(address token, uint newVal) external onlyTokenValueOracle {
    _requireValidToken(token);
    uint oldVal = s_tokenToCoreValues[token];
    s_tokenToCoreValues[token] = newVal;
    emit SetTokenValueInCores(token, oldVal, newVal);
  }  

  function setMinLostCredentialsInactivityPeriod(uint newMin) external onlyGovDelegate {
    uint oldMin = s_lostCredentialsInactivityPeriod;
    s_lostCredentialsInactivityPeriod = newMin;
    emit SetMinLostCredentialsInactivityPeriod(oldMin, newMin);
  }  

  function setFixedTxGasFee(uint newFee) external onlyGovDelegate {
    uint oldFee = s_fixedTxGasFee;
    s_fixedTxGasFee = newFee;
    emit SetFixedTxGasFee(oldFee, newFee);
  }    

  function setScammerGasFactor(uint newFactorMilliCores) external onlyGovDelegate {
    require(newFactorMilliCores >= 1000, "scammer factor too small");
    uint oldFactor = g_scammersGasFactorMilliCores;
    g_scammersGasFactorMilliCores = newFactorMilliCores;
    emit SetScammerGasFactor(oldFactor, newFactorMilliCores);
  }    

  function recoverLostCredentials(string memory originName, string memory lostUser, 
                                  string memory recoveredUser, address[] memory tokens, 
                                  GasParams memory gparams) public onlyGovDelegate {
    // called by GovDelegate after enough proof has been provided offchain that recoveredAccount is indeed owned by the orig user
    _requireValidUsername(lostUser);
    _requireValidUsername(recoveredUser);  
    _requireActiveUser(lostUser);
    _requireActiveUser(recoveredUser);
    
    uint inactivityPeriod = block.timestamp - s_activeUsers[lostUser].lastActiveTime;
    require(inactivityPeriod > s_lostCredentialsInactivityPeriod, "insufficient inactivity period");

    _updateUserTimestamp(recoveredUser);

    uint coreToAdd = s_balances[lostUser][CORE];
    s_balances[lostUser][CORE] = 0;
    s_balances[recoveredUser][CORE] += coreToAdd;

    // its the caller's responsibility to make sure that all tokens owned by origUser are passed here

    for (uint i = 0; i < tokens.length; i++) {
      address _token = tokens[i];
      _requireValidToken(_token);
      uint tokenToAdd = s_balances[lostUser][_token];
      s_balances[lostUser][_token] = 0;
      s_balances[recoveredUser][_token] += tokenToAdd;
    }
    _payGasFee(1, originName, gparams);
    emit RecoverLostCredentials(lostUser, recoveredUser);
  }  

  function setTokenValueOracle(address newAddress) external onlyGovDelegate {
    require(newAddress != address(0), "zero addr");
    address oldAddress = s_tokenValueOracle;
    s_tokenValueOracle = newAddress;
    emit SetTokenValueOracle(oldAddress, newAddress);
  }

  function setScammerDetectorOracle(address newAddress) external onlyGovDelegate {
    require(newAddress != address(0), "zero addr");
    address oldAddress = s_scammerDetectorOracle;
    s_scammerDetectorOracle = newAddress;
    emit SetScammerDetectorOracle(oldAddress, newAddress);
  }

  function removeFromTokenTypesInVaultArray(address[] memory _tokens) external onlyGovDelegate {
    // rescue func for when s_tokenTypesInVault grows too large
    for (uint i = 0; i < _tokens.length; i++) {
      _removeFromTokenTypesInVaultArray(_tokens[i]);
    }
  }

  function setGovDelegate(address newDelegate) external onlyGovernance {
    require(newDelegate != address(0), "zero addr");
    address oldDelegate = s_govDelegate;
    s_govDelegate = newDelegate;
    emit SetGovDelegate(oldDelegate, newDelegate);
  }

  function getAllUserAssets(string memory username, address[] memory tokensToCheck) external view returns (uint[] memory){
    _requireValidUsername(username);
    _requireActiveUser(username);
    
    uint len = tokensToCheck.length;
    uint[] memory _userBalances = new uint[](len);

    for (uint i = 0; i < len; i++) {
      address _token = tokensToCheck[i];
      require(_token != address(0), "bad token");
      uint _balance = s_balances[username][_token];
      _userBalances[i] = _balance; // possibly CORE
    }
    return _userBalances;
  }

  function transferCoreFromVault(TxRecord memory r) public nonReentrant onlyGovDelegate {
    // transfer directions:
    //    vault => EOA
    //    vault => vault (=shortCircuit)
    require(r.token == address(0), "cannot pass token to this function");
    require(r.amount > 0, "Core amount should be positive");
    _requireValidUsername(r.originName);
    require(_validTokens(r.gparams.gasTokens), "invalid tokens");

    _requireValidUsername(r.fromName);
    require(_eq(r.originName, r.fromName), "origin must be equal to from-name");

    _updateUserTimestamp(r.originName);

    require(_validUsername(r.fromName), "fromName must be passed");
    require(r.fromAddress == address(0), "this operation cannot use fromAddress");

    // transfer token fron within contract - either shortCircuit inside or transfer to an external address (or both)

    require(address(this).balance >= r.amount, "not enough Core in vault");
    require(s_balances[r.fromName][CORE] >= r.amount, "not enough Core in user's balance");

    s_balances[r.fromName][CORE] -= r.amount;

    if (r.allowShortCircuit && _canTransferTo(r.toName)) {
      s_balances[r.toName][CORE] += r.amount;
      require(s_balances[r.toName][CORE] <= s_maxCorePerUser, "cannot exceed maxCorePerUser");
    } else if (r.toAddress != address(0)) {
      _transferCoreOutOfVault(r.toAddress, r.amount);
    } else {
      revert("cannot perform operation");
    }
    _payGasFee(1, r.originName, r.gparams);
    emit TransferCoreFromVault(r.originName, r.toName, r.toAddress, r.amount);
  }


  function transferCoreFromExternalAddress(TxRecord memory r) public payable nonReentrant onlyGovDelegate {
    // EOA => vault
    require(r.token == address(0), "cannot pass token to this function");
    require(r.amount == 0, "Core amount should be taken from msg.value");
    _requireValidUsername(r.originName);
    require(_validTokens(r.gparams.gasTokens), "invalid tokens");

    _updateUserTimestamp(r.originName);

    require(_isEmpty(r.fromName), "fromName cannot be used");
    require(r.fromAddress != address(0), "this operation requires fromAddress");

    require(_validUsername(r.toName) && _canTransferTo(r.toName), "cannot transfer Core to toName");

    s_balances[r.toName][CORE] += msg.value;
    require(s_balances[r.toName][CORE] <= s_maxCorePerUser, "cannot exceed maxCorePerUser");
    
    _payGasFee(1, r.originName, r.gparams);
    emit TransferCoreFromExternalAddress(r.originName, r.fromAddress, r.toName, r.amount);
  }


  function transferToken(TxRecord memory r) public nonReentrant onlyGovDelegate {
    // transfer directions:
    //    EOA => vault
    //    vault => EOA
    //    vault => vault (=shortCircuit)
    _requireValidUsername(r.originName);
    _requireValidToken(r.token);
    require(_validTokens(r.gparams.gasTokens), "invalid tokens");

    _updateUserTimestamp(r.originName);

    bool tokensOutsideOfVault = _isEmpty(r.fromName) && r.fromAddress != address(0);

    if (tokensOutsideOfVault) {
      _transferTokensFromExternalAddressIntoVault(r);
    } else {
      _transferTokensFromWithinVault(r);
    }

    _payGasFee(1, r.originName, r.gparams);
    emit TransferToken(r.originName, r.fromAddress, r.fromName, r.toName, r.toAddress, r.token, r.amount);
  }


  function performBatchOperations(string memory originName, BatchOperation[] memory ops, GasParams memory gparams) external onlyGovDelegate { // nonReentrant will result in revert here
    if (ops.length == 0) {
      return;
    }
    _updateUserTimestamp(originName);

    uint numOps = ops.length;
    s_disableGasPayments = true; // single gas payment out of loop
    for (uint i = 0; i < numOps; i++) {
      require(ops[i].data.length > 0, "cannot transfer() Core directly into vault"); // => this.call{value: value}("");
      // note that ops[i].data is assumed to be packed with the function signature e.g.:
      //    bytes4 functionSignature = bytes4(keccak256(bytes(_signatureStr)));
      //    ops[i].data = abi.encodePacked(functionSignature, _calldata);
      (bool ok,) = address(this).call{ value: ops[i].value }(ops[i].data);
      require(ok, "operation failed");
    }    
    s_disableGasPayments = false;

    _payGasFee(numOps, originName, gparams);
    emit BatchOperations(originName, numOps);
  }



  function _transferTokensFromWithinVault(TxRecord memory r) private {
    // transfer token fron within the vault contract - either shortCircuit inside or transfer to an external address
    _requireValidUsername(r.fromName);
    require(_eq(r.originName,r.fromName), "origin <> from");
    require(r.fromAddress == address(0), "fromAddress cannot be used");

    s_balances[r.fromName][r.token] -= r.amount;

    if (r.allowShortCircuit && _canTransferTo(r.toName)) {
      s_balances[r.toName][r.token] += r.amount;
    } else if (r.toAddress != address(0)) {
      _transferTokensOutOfVault(r.token, r.toAddress, r.amount);
    } else {
      revert("cannot perform operation");
    }
  }

  function _payGasFee(uint numTx, string memory originName, GasParams memory gparams) private {
    // gas fees must be all in-vault
    if (s_disableGasPayments) {
      return;
    }

    string memory payer = originName; // only origin pays gas
    _requireValidUsername(payer);
    _requireActiveUser(payer);

    uint gasdropsToSubtract = _min(s_activeUsers[payer].numGasdropsLeft, numTx);
    s_activeUsers[payer].numGasdropsLeft -= gasdropsToSubtract;
    numTx -= gasdropsToSubtract;

    if (numTx == 0) {
      return;
    }

    uint gasToPay = numTx * s_fixedTxGasFee; 
    if (s_activeUsers[payer].suspectedScammer) {
      gasToPay = (gasToPay * g_scammersGasFactorMilliCores)/1000;
    }
    uint paid;

    if (gparams.gasPaymentStartsWithCore) {
      paid = _payGasWithCore(gasToPay, payer);
    } else {
      // start with tokens
      paid = _payGasWithTokens(gasToPay, payer, gparams);
    }
    gasToPay -= paid;

    if (gasToPay == 0) {
      return;
    }

    bool alreadyPaidWithCore = gparams.gasPaymentStartsWithCore;

    // use the 'other' to pay the rest
    if (alreadyPaidWithCore) {
      // pay the rest with tokens
      paid = _payGasWithTokens(gasToPay, payer, gparams);
    } else {
      // pay the rest with Core
      paid = _payGasWithCore(gasToPay, payer);
    }
    gasToPay -= paid;

    require(gasToPay == 0, "payer failed to pay gas fees");
  }


  function _payGasWithCore(uint gasToPay, string memory _payer) private returns(uint) {
    // pay with in-vault Core
    uint paidInCore = _min(s_balances[_payer][CORE], gasToPay);
    s_balances[_payer][CORE] -= paidInCore;
    s_balances[GAS_FEE_ACCOUNT][CORE] += paidInCore;
    return paidInCore;
  }

  function _payGasWithTokens(uint gasToPay, string memory payer, GasParams memory gparams) private returns(uint) {
    // pay with in-vault token
    uint totalPaidSofar = 0;

    // iterate tokens in-order to pay gas fees
    for (uint i = 0; i < gparams.gasTokens.length; i++) {
      uint paidNow = _payGasWithSingleToken(payer, gparams.gasTokens[i], gasToPay-totalPaidSofar);
      totalPaidSofar += paidNow;
      if (totalPaidSofar >= gasToPay) {
        break;
      }
    }

    return totalPaidSofar;
  }


  function _payGasWithSingleToken(string memory _payer, address _token, uint gasLeftToPay) private returns(uint) {  
    _requireValidToken(_token);
    uint userTokenBalance = s_balances[_payer][_token];
    if (userTokenBalance == 0) { 
      return 0;
    }

    uint tokenValueInCore = _getTokenValueInCore(_token);
    uint userTokenBalanceInCore = userTokenBalance * tokenValueInCore;

    uint paidInTokensNow;
    uint paidInCoreNow;
    if (userTokenBalanceInCore >= gasLeftToPay) {
      paidInCoreNow = gasLeftToPay;
      paidInTokensNow = gasLeftToPay / tokenValueInCore;
    } else {
      paidInCoreNow = userTokenBalanceInCore;
      paidInTokensNow = userTokenBalance;
    }
      
    s_balances[_payer][_token] -= paidInTokensNow;
    s_balances[GAS_FEE_ACCOUNT][_token] += paidInTokensNow;       

    return paidInCoreNow; 
  }

  function _getTokenValueInCore(address _token) private view returns(uint) {
    uint tokenValueInCore = s_tokenToCoreValues[_token];
    if (tokenValueInCore == 0) {
      revert CoreValueNotSetForToken(_token);
    }
    return tokenValueInCore;
  }

  function _requireUserNotAlreadyRegistered(string memory username) private view {
    uint _lastActiveTime = s_activeUsers[username].lastActiveTime;
    if (_lastActiveTime > 0) {
      revert UserAlreadyRegistered(username, _lastActiveTime);
    }
  }

  function _requireValidToken(address _token) private pure {
    if (!_validToken(_token)) {
      revert InvalidToken(_token);
    }
  }
  
  function _requireActiveUser(string memory username) private view {
    if (!_isActiveUser(username)) {
      revert NotAnActiveUser(username);
    }
  }

  function _requireValidUsername(string memory username) private view{
    if (!_validUsername(username)) {
      revert InvalidUsername(username);
    }
  }

  function _validUsername(string memory username) private view returns(bool) {
    return bytes(username).length >= s_minUsernameLength;
  }

  function _isEmpty(string memory s) private pure returns(bool) {
    return bytes(s).length == 0;
  }

  function _transferCoreOutOfVault(address _toAddress, uint _amount) private {
    require(address(this).balance >= _amount, "not enough Core in vault");
    (bool ok,) = payable(_toAddress).call{ value: _amount }("");
    require(ok, "Core transfer failed");
  }

  function _transferTokensOutOfVault(address _token, address _toAddress, uint _amount) private {
    require(s_tokenTotals[_token] >= _amount, "not enough tokens in vault");
    bool ok = IERC20(_token).transfer(_toAddress, _amount);
    require(ok, "token transfer failed");

    s_tokenTotals[_token] -= _amount;
    if (s_tokenTotals[_token] == 0) {
      _removeFromTokenTypesInVaultArray(_token);
    }
  }

  function _removeFromTokenTypesInVaultArray(address _token) private {
    _requireValidToken(_token);
    require(s_tokenTotals[_token] == 0, "token balance must be zero");
    uint len = s_tokenTypesInVault.length;
    for (uint i = 0; i < len; i++) {
      if (s_tokenTypesInVault[i] == _token) {
        s_tokenTypesInVault[i] = s_tokenTypesInVault[len-1]; // order is not important
        s_tokenTypesInVault.pop();
        return;
      }
    }
    emit TokenRemovedFromInVaultArray(_token);
  }

  function _registerUser(string memory username) private {
    _requireValidUsername(username);
    _requireUserNotAlreadyRegistered(username);
    uint _now = block.timestamp;
    s_activeUsers[username] = VaultUser({lastActiveTime: _now, 
                                          numGasdropsLeft: s_numGasdropsForNewcomers, 
                                          suspectedScammer: false });
  }

  function _transferTokensFromExternalAddressIntoVault(TxRecord memory r) private {
    require(_validUsername(r.toName) && _canTransferTo(r.toName), "cannot transfer to toName");

    s_balances[r.toName][r.token] += r.amount;
    if (s_tokenTotals[r.token] == 0) {
      s_tokenTypesInVault.push(r.token); // new token
    }
    s_tokenTotals[r.token] += r.amount;

    IERC20 _token = IERC20(r.token);
    address _owner = r.fromAddress;
    address _spender = address(this);
    uint _allowance = _token.allowance(_owner, _spender);
    require(_allowance >= r.amount, "vault should have an allowance of >= amount");

    bool ok = _token.transferFrom(r.fromAddress, address(this), r.amount);
    require(ok, "token transfer failed");
  }


  function _validTokens(address[] memory tokens) private pure returns(bool) {
    for (uint i = 0; i < tokens.length; i++) {
      if (!_validToken(tokens[i])) {
        return false;
      }
    }
    return true;
  }

  function _validToken(address token) private pure returns(bool) {
    return token != address(0) && token != CORE;
  }

  function _canTransferTo(string memory username) private view returns(bool) {
    return _validUsername(username) && _isActiveUser(username) && !s_restrictedUsers[username];
  }

  function _isActiveUser(string memory username) private view returns(bool) {
    return s_activeUsers[username].lastActiveTime > 0;
  }

  function _updateUserTimestamp(string memory _username) private {
    require(_isActiveUser(_username), "not a user");
    uint _now = block.timestamp;
    s_activeUsers[_username].lastActiveTime = _now;
  }

  function _min(uint a, uint b) private pure returns(uint) {
    return a < b ? a : b;
  }

  function _eq(string memory str1, string memory str2) private pure returns(bool) {
    return keccak256(abi.encodePacked(str1)) == keccak256(abi.encodePacked(str2));
  }
}


//   zzzz limit num Cores per account
//   zzzz gas payments > can only be applied to origin!;
//   zzzz auto-airDrop =='GasDrop' mode;
//   zzz make upgradble;
//   zzz fixed gas per Tx; maybe 3-times for suspected scammer;
//   zzzz add suspectedScammer list gov-populated (AI engine);
// ---
