// SPDX-License-Identifier: Apache2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import './uniswap-v3/ISwapRouter.sol';


interface IERC20 {
  function transfer(address to, uint256 value) external returns (bool);
  function transferFrom(address from, address to, uint256 value) external returns (bool);
  function allowance(address owner, address spender) external view returns (uint256);
  function approve(address spender, uint256 value) external returns (bool);
}



contract CoreVault is Initializable, ReentrancyGuardUpgradeable {
  
  uint[32] public __gap; // sanity gap for future stateful base-contracts
  
  uint public constant DEF_LOST_CREDENTIALS_MIN_INACTIVITY_PERIOD = 10 weeks;
  uint public constant DEF_MIN_USERNAME_LEN = 4;
  uint public constant DEF_MAX_CORE_PER_USER = 4000e18;
  uint public constant DEF_FIXED_TX_GAS_FEE = 1e18/100;
  uint public constant DEF_SCAMMER_GAS_FACTOR_MILLICORE = 3*1000;  
  uint24 public constant DEF_UNISWAP_FEE_TIER = 3000;  // 3000 == 0.3% fee
  
  address public constant CORE = address(0x11);
  string public constant GAS_FEE_ACCOUNT = "gas_fee_account"; 


  uint24 public s_uniswapFeeTier; 
  ISwapRouter public s_uniswapV3Router;  // on Ethereum: 0xE592427A0AEce92De3Edee1F18E0157C05861564

  address public s_governance; // GOV_HUB = 0x0000000000000000000000000000000000001006;

  uint public s_scammersGasFactorMilliCores;
  uint public s_fixedTxGasFee;
  uint public s_lostCredentialsInactivityPeriod;
  uint public s_maxCorePerUser;
  uint public s_minUsernameLength;

  uint public s_numGasdropsForNewcomers; // to be assigned to each new user
  address public s_govDelegate;
  address public s_tokenValueOracle;
  address public s_scamDetectorOracle;
  bool private s_disableGasPayments;

  address[] public s_tokenTypesInVault; // CORE excluded

  mapping(string => mapping(address => uint)) public s_balances; // CORE included!

  mapping(string => mapping(string => uint)) public s_delegatedGasPaymentAllowance; // in number of Tx

  mapping(string => VaultUser) public s_activeUsers;
  
  mapping(string => bool) public s_restrictedUsers; // if set - active user may not receive new assets
  
  mapping(address => uint) public s_tokenTotals; // CORE excluded (its total can always be taken from contract's balance)
  
  mapping(address => uint) public s_gasTokenCoreValue; // token-to-CORE values mandatory for gas-paying tokens
  //------------


  event VaultInitialized(address _governance, address _govDelegate, uint _defaultNumGasdrops);

  event RegisterNewUser(string indexed username);

  event UnregisterUser(string indexed username);

  event RestrictUserForReceival(string indexed username, bool oldRestict, bool newRestict);

  event SetMinUsernameLength(uint oldLen, uint newLen);

  event SetNumGasdropsForNewcomers(uint oldNum, uint newNum);

  event SetUniswapV3Router(address indexed oldSwapRouter, address indexed newSwapRouter);

  event SetUniswapFeeTier(uint24 oldTier, uint24 newTier);
  
  event SetScammerGasFactor(uint oldFactor, uint newFactor);

  event SetMaxCorePerUser(uint oldMax, uint newMax);

  event SetTokenValueOracle(address indexed oldAddress, address indexed newAddress);

  event SetScamDetectorOracle(address indexed oldAddress, address indexed newAddress);

  event SetMinLostCredentialsInactivityPeriod(uint oldMin, uint newMin);

  event SetScammerStatusForUser(string indexed username, bool oldSuspectedScammer, bool newSuspectedScammer);

  event SetFixedTxGasFee(uint oldFee, uint newFee);

  event RecoverLostCredentials(string indexed origUser, string indexed recoveredUser);

  event TokenRemovedFromInVaultArray(address indexed _token);

  event SetGasTokenCoreValue(address indexed token, uint oldVal, uint newVal);

  event SetDelegatedGasPaymentAllowance(string indexed gasPayerDelegate, string indexed originName, uint oldTxAllowance, uint newTxAllowance);

  event SetGovDelegate(address indexed oldDelegate, address indexed newDelegate);

  event TransferCoreFromVault(string indexed originName, string indexed toName, address indexed toAddress, uint amount);

  event TransferCoreFromExternalAddress(address indexed txOrigin, address indexed fromAddress, string indexed toName, uint amount);

  event TransferTokenFromExternalAddress(address indexed tokenOwner, string indexed toUsername, address indexed token, uint amount);

  event TransferToken(string indexed originName, address fromAddress, string indexed fromName, string indexed toName, address toAddress, address token, uint amount);
  
  event BatchOperations(string indexed originName, uint numOps);
  //------------


  error TokenMayNotBeUsedForGasPayment(address token);

  error InvalidToken(address token);
  
  error NotAnActiveUser(string username);
  
  error InvalidUsername(string username);

  error UserAlreadyRegistered(string username, uint lastActiveTime);
  //------------


  struct SwappableGasToken {
    address origToken;
    address tokenToSwapTo; // non-swappable if tokenToSwapTo = zero
  }

  struct GasParams {
    string gasPayerDelegate;
    bool gasPaymentStartsWithCore;
    SwappableGasToken[] gasTokens;
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
    bool isSuspectedScammer;
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

  modifier onlyScamDetectorOracle() {
    require(msg.sender == s_scamDetectorOracle, "not scam-detector oracle");
    _;
  }    
  //------------


  receive() external payable { 
    revert("cannot pass Core to vault without specifying destination"); 
  }

  //constructor() -> upgradeable contract, can't use

  function initialize(address _gov, address _govDelegate, uint _defaultNumGasdrops, address _uniswapV3Router) external initializer {
    __ReentrancyGuard_init();
    require(_gov != address(0), "missing governance addr");
    require(_govDelegate != address(0), "missing govDelegate addr");

    s_scammersGasFactorMilliCores = DEF_SCAMMER_GAS_FACTOR_MILLICORE;
    s_fixedTxGasFee = DEF_FIXED_TX_GAS_FEE;
    s_lostCredentialsInactivityPeriod = DEF_LOST_CREDENTIALS_MIN_INACTIVITY_PERIOD;
    s_maxCorePerUser = DEF_MAX_CORE_PER_USER;
    s_minUsernameLength = DEF_MIN_USERNAME_LEN;
    s_uniswapFeeTier = DEF_UNISWAP_FEE_TIER;

    s_governance = _gov;
    s_govDelegate = _govDelegate;
    s_numGasdropsForNewcomers = _defaultNumGasdrops;
    s_uniswapV3Router = ISwapRouter(_uniswapV3Router);
    _registerUser(GAS_FEE_ACCOUNT); // avoid malicious users from registering this username
    emit VaultInitialized(_gov, _govDelegate, _defaultNumGasdrops);
  }

  function registerUser(string memory username) external onlyGovDelegate {
    _registerUser(username);
    emit RegisterNewUser(username);
  }

  function setScammerStatusForUser(string memory username, bool newStatus) external onlyScamDetectorOracle {
    _requireActiveUser(username);
    bool oldStatus = s_activeUsers[username].isSuspectedScammer;
    s_activeUsers[username].isSuspectedScammer = newStatus;
    emit SetScammerStatusForUser(username, oldStatus, newStatus);
  }

  function restrictUserForReceival(string memory username, bool restict) external onlyGovDelegate {
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
  
  function setUniswapFeeTier(uint24 newTier) external onlyGovDelegate {
    uint24 oldTier = s_uniswapFeeTier;
    s_uniswapFeeTier = newTier;
    emit SetUniswapFeeTier(oldTier, newTier);
  }  

  function setUniswapV3Router(address newSwapRouter) external onlyGovDelegate {
    // newSwapRouter may be zero thus disabling token swapping
    address oldSwapRouter = address(s_uniswapV3Router);
    s_uniswapV3Router = ISwapRouter(newSwapRouter);
    emit SetUniswapV3Router(oldSwapRouter, newSwapRouter);
  }  

  function setMaxCorePerUser(uint newMax) external onlyGovDelegate {
    uint oldMax = s_maxCorePerUser;
    s_maxCorePerUser = newMax;
    emit SetMaxCorePerUser(oldMax, newMax);
  }  

  function setGasTokenValueInCore(address token, uint newValueInCore) external onlyTokenValueOracle {
    // newVal can be set to zero indicating token may not be used for gas payment
    _requireValidToken(token);
    uint oldValueInCore = s_gasTokenCoreValue[token];
    s_gasTokenCoreValue[token] = newValueInCore;
    emit SetGasTokenCoreValue(token, oldValueInCore, newValueInCore);
  }  

  function setDelegatedGasPaymentAllowance(string memory gasPayerDelegate, 
                                           string memory originName, 
                                           uint newTxAllowance) external onlyGovDelegate {
    _requireActiveUser(gasPayerDelegate);
    _requireActiveUser(originName);

    uint oldTxAllowance = s_delegatedGasPaymentAllowance[gasPayerDelegate][originName];
    s_delegatedGasPaymentAllowance[gasPayerDelegate][originName] = newTxAllowance;
    emit SetDelegatedGasPaymentAllowance(gasPayerDelegate, originName, oldTxAllowance, newTxAllowance);
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
    uint oldFactor = s_scammersGasFactorMilliCores;
    s_scammersGasFactorMilliCores = newFactorMilliCores;
    emit SetScammerGasFactor(oldFactor, newFactorMilliCores);
  }    


  function recoverLostCredentials(string memory originName, string memory lostUser, 
                                  string memory recoveredUser, address[] memory tokens, 
                                  GasParams memory gparams) external nonReentrant onlyGovDelegate {
    // called by GovDelegate after enough proof has been provided offchain that recoveredAccount is indeed owned by the orig user
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
    // newAddress may be set to null address to disable token value injection
    address oldAddress = s_tokenValueOracle;
    s_tokenValueOracle = newAddress;
    emit SetTokenValueOracle(oldAddress, newAddress);
  }

  function setScamDetectorOracle(address newAddress) external onlyGovDelegate {
    // newAddress may be set to null address to disable scammer detection
    address oldAddress = s_scamDetectorOracle;
    s_scamDetectorOracle = newAddress;
    emit SetScamDetectorOracle(oldAddress, newAddress);
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


  function transferCoreFromExternalAddress(string memory toUsername) external payable nonReentrant { // not onlyGovDelegate!
    // invoked by an external EOA to pass Core into vault 
    _verifyCanTransferToUser(toUsername);

    _updateUserTimestamp(toUsername);

    _addCoreToUserBalance(toUsername, msg.value);
    
    //_payGasFee(..) -- gas paid by EOA 
    emit TransferCoreFromExternalAddress(tx.origin, msg.sender, toUsername, msg.value);
  }


  function transferTokenFromExternalAddress(address token, uint amount, string memory toUsername) external nonReentrant { // not onlyGovDelegate!
    // invoked by an external EOA to pass token into vault 
    _verifyCanTransferToUser(toUsername);
    
    _updateUserTimestamp(toUsername);

    _transferTokensFromExternalAddressIntoVault(token, amount, toUsername);
    
    //_payGasFee(..) -- gas paid by EOA 
    emit TransferTokenFromExternalAddress(msg.sender, toUsername, token, amount);
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


  function transferTokenFromVault(TxRecord memory r) public nonReentrant onlyGovDelegate {
    // transfer tokens from within vault:
    //    vault => EOA
    //    vault => vault (=shortCircuit)
    require(r.fromAddress == address(0), "cannot use fromAddress");
    _requireValidUsername(r.originName);
    _requireValidUsername(r.fromName);
    _requireValidToken(r.token);
  require(_validTokens(r.gparams.gasTokens), "invalid tokens");

    _updateUserTimestamp(r.originName);

  _transferTokensFromWithinVault(r);

    _payGasFee(1, r.originName, r.gparams);
    emit TransferToken(r.originName, r.fromAddress, r.fromName, r.toName, r.toAddress, r.token, r.amount);
  }


  function performBatchOperations(string memory originName, 
                                  BatchOperation[] memory ops, 
                                  GasParams memory gparams) external onlyGovDelegate { // nonReentrant will result in revert here
    if (ops.length == 0) {
      return;
    }
    _updateUserTimestamp(originName);

    s_disableGasPayments = true; // instead: single gas payment outside of loop
    for (uint i = 0; i < ops.length; i++) {
      require(ops[i].data.length > 0, "cannot transfer() Core directly into vault"); // => this.call{value: value}("");
      // note that ops[i].data is assumed to be packed with the function signature e.g.:
      //    bytes4 functionSignature = bytes4(keccak256(bytes(_signatureStr)));
      //    ops[i].data = abi.encodePacked(functionSignature, _calldata);
      (bool ok,) = address(this).call{ value: ops[i].value }(ops[i].data); //not @unsafe since the call loops back into the vault
      require(ok, "operation failed");
    }    
    s_disableGasPayments = false;

    _payGasFee(ops.length, originName, gparams);
    emit BatchOperations(originName, ops.length);
  }

  function numTokenTypesInVault() external view returns (uint) {
    return s_tokenTypesInVault.length;
  }

  function getAllUserAssets(string memory username, address[] memory tokensToCheck) external view returns (uint[] memory){
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

    _requireActiveUser(originName);

    string memory _delegate = _getGasDelegate(gparams);
    bool delegatedGasPayment = _notEmpty(_delegate) && !_eq(_delegate, originName);

    string memory payer; 
    if (delegatedGasPayment) {
      _subtractFromGasTxAllowance(_delegate, originName, numTx);
      payer = _delegate;
    } else {
      payer = originName;  // no delegation - origin pays
    }

    uint gasdropsToSubtract = _min(s_activeUsers[payer].numGasdropsLeft, numTx);
    s_activeUsers[payer].numGasdropsLeft -= gasdropsToSubtract;
    numTx -= gasdropsToSubtract;

    if (numTx == 0) {
      return;
    }

    uint gasToPay = numTx * s_fixedTxGasFee; 
    if (s_activeUsers[payer].isSuspectedScammer) {
      gasToPay = (gasToPay * s_scammersGasFactorMilliCores)/1000;
    }

    uint paid;
    if (gparams.gasPaymentStartsWithCore) {
      paid = _payGasWithCore(payer, gasToPay);
    } else {
      paid = _payGasWithTokens(payer, gasToPay, gparams);
    }
    gasToPay -= paid;

    if (gasToPay == 0) {
      return;
    }

    bool alreadyPaidWithCore = gparams.gasPaymentStartsWithCore;

    // use the 'other' method to pay the rest of the gas
    if (alreadyPaidWithCore) {
      paid = _payGasWithTokens(payer, gasToPay, gparams);
    } else {
      paid = _payGasWithCore(payer, gasToPay);
    }
    gasToPay -= paid;

    require(gasToPay == 0, "payer failed to pay gas fees");
  }

  function _subtractFromGasTxAllowance(string memory gasDelegate, string memory originName, uint numTx) private {
    require(s_delegatedGasPaymentAllowance[gasDelegate][originName] >= numTx, "No gas allowance for origin");
    s_delegatedGasPaymentAllowance[gasDelegate][originName] -= numTx;
  }

  function _getGasDelegate(GasParams memory gparams) private view returns(string memory) {
    string memory delegate = gparams.gasPayerDelegate;
    if (_notEmpty(delegate)) {
      _requireActiveUser(delegate);
    }
    return delegate;
  }

  function _payGasWithCore(string memory _payer, uint gasToPay) private returns(uint) {
    // only use in-vault Core for gas payment
    uint paidInCore = _min(s_balances[_payer][CORE], gasToPay);
    s_balances[_payer][CORE] -= paidInCore;
    s_balances[GAS_FEE_ACCOUNT][CORE] += paidInCore;
    return paidInCore;
  }

  function _payGasWithTokens(string memory payer, uint gasToPay, GasParams memory gparams) private returns(uint) {
    // only use in-vault tokens for gas payment
    uint totalPaidSofar = 0;

    // iterate over gas tokens in-order
    for (uint i = 0; i < gparams.gasTokens.length; i++) {
      uint paidNow = _payGasWithSingleToken(payer, gparams.gasTokens[i], gasToPay-totalPaidSofar);
      totalPaidSofar += paidNow;
      if (totalPaidSofar >= gasToPay) {
        break;
      }
    }

    return totalPaidSofar;
  }

  function _payGasWithSingleToken(string memory _payer, SwappableGasToken memory _gasToken, uint toPayInCore) private returns(uint) {  
    address _token = _gasToken.origToken;
    _requireValidToken(_token);
    uint userTokenBalance = s_balances[_payer][_token];
    if (userTokenBalance == 0) { 
      return 0;
    }

    uint tokenValueInCore = _getTokenValueInCore(_token);
    uint userTokenBalanceInCore = userTokenBalance * tokenValueInCore;

    uint paidInTokensNow;
    uint paidInCoreNow;
    if (userTokenBalanceInCore >= toPayInCore) {
      paidInCoreNow = toPayInCore;
      paidInTokensNow = toPayInCore / tokenValueInCore;
    } else {
      paidInCoreNow = userTokenBalanceInCore;
      paidInTokensNow = userTokenBalance;
    }

    s_balances[_payer][_token] -= paidInTokensNow;

    address _tokenToSwapTo = _gasToken.tokenToSwapTo;

    bool tryToSwap = _tokenToSwapTo != address(0) && _tokenToSwapTo != _token;

    if (tryToSwap && _swapWasSuccessful(_token, paidInTokensNow, _tokenToSwapTo)) {
      // swapped token was added to s_balances[GAS_FEE_ACCOUNT] 
    } else {
      s_balances[GAS_FEE_ACCOUNT][_token] += paidInTokensNow; // no swapping; use orig token
    }
    return paidInCoreNow; 
  }


  function _swapWasSuccessful(address _token, uint paidInTokensNow, address tokenToSwapTo) private returns(bool) {
    uint _amountReceived = _uniswapTokens(_token, paidInTokensNow, tokenToSwapTo);
    if (_amountReceived == 0) {
      return false; // swap failed
    }
    // update vault state mappings
    _subtractFromTokenTotals(_token, paidInTokensNow);
    _addToTokenTotals(tokenToSwapTo, _amountReceived);
    s_balances[GAS_FEE_ACCOUNT][tokenToSwapTo] += _amountReceived;
    return true;
  }


  function _uniswapTokens(address _tokenIn, uint _amountIn, address _tokenOut) private returns(uint) {
    // currently only Uniswap-V3 is supported
    if (address(s_uniswapV3Router) == address(0)) {
      return 0; 
    }
    _approveTokensForUniswapRouter(_tokenIn, _amountIn);
    
    address _vault = address(this); 
    ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
          tokenIn: _tokenIn,
          tokenOut: _tokenOut,
          fee: s_uniswapFeeTier,
          recipient: _vault,  // swap directly into vault
          deadline: block.timestamp,
          amountIn: _amountIn,
          amountOutMinimum: 0,
          sqrtPriceLimitX96: 0 // set sqrtPriceLimitx96 to be 0 to ensure we swap our exact input amount.
    });

    uint amountOut = s_uniswapV3Router.exactInputSingle(params); //@unsafe?
    return amountOut;
  }

  function _approveTokensForUniswapRouter(address _tokenIn, uint _amountIn) private {
    require(address(s_uniswapV3Router) != address(0), "uniswap router not set");
    bool ok = IERC20(_tokenIn).approve(address(s_uniswapV3Router), _amountIn);
    require(ok, "token approval failed");
  }

  function _getTokenValueInCore(address _token) private view returns(uint) {
    uint tokenValueInCore = s_gasTokenCoreValue[_token];
    if (tokenValueInCore == 0) {
      revert TokenMayNotBeUsedForGasPayment(_token);
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
    _requireValidUsername(username);
    if (!_isActiveUser(username)) {
      revert NotAnActiveUser(username);
    }
  }

  function _requireValidUsername(string memory username) private view {
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
    (bool ok,) = payable(_toAddress).call{ value: _amount }(""); //@unsafe
    require(ok, "Core transfer failed");
  }

  function _transferTokensOutOfVault(address _token, address _toAddress, uint _amount) private { 
    require(s_tokenTotals[_token] >= _amount, "not enough tokens in vault");
    bool ok = IERC20(_token).transfer(_toAddress, _amount); //@unsafe
    require(ok, "token transfer failed");
    _subtractFromTokenTotals(_token, _amount);
  }

  function _subtractFromTokenTotals(address _token, uint _amount) private {
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
                                          isSuspectedScammer: false });
  }


  function _transferTokensFromExternalAddressIntoVault(address token, uint amount, string memory toUsername) private {
    if (amount == 0) {
      return;
    }
    _requireValidToken(token);
    require(_validUsername(toUsername) && _canTransferTo(toUsername), "cannot transfer to toName");

    s_balances[toUsername][token] += amount;
    _addToTokenTotals(token, amount);

    address _tokenOwner = msg.sender;
    _verifySufficientAllowance(token, _tokenOwner, amount);

    bool ok = IERC20(token).transferFrom(_tokenOwner, address(this), amount); //@unsafe
    require(ok, "token transfer failed");
  }


  function _verifySufficientAllowance(address token, address _tokenOwner, uint amount) private view {
    address _spender = address(this);
    uint _allowance = IERC20(token).allowance(_tokenOwner, _spender);
    require(_allowance >= amount, "vault should have an allowance of >= amount");
  }

  function _addCoreToUserBalance(string memory toUsername, uint coreAmount) private {
    s_balances[toUsername][CORE] += coreAmount;
    require(s_balances[toUsername][CORE] <= s_maxCorePerUser, "cannot exceed maxCorePerUser");    
  }

  function _addToTokenTotals(address _token, uint _amount) private {
    if (s_tokenTotals[_token] == 0) {
      s_tokenTypesInVault.push(_token); // new token
    }
    s_tokenTotals[_token] += _amount;
  }

  function _validTokens(SwappableGasToken[] memory tokens) private pure returns(bool) {
    for (uint i = 0; i < tokens.length; i++) {
      if (!_validToken(tokens[i].origToken)) {
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

  function _verifyCanTransferToUser(string memory toUsername) private view {
    require(_isActiveUser(toUsername), "not a user");
    require(_canTransferTo(toUsername), "cannot transfer Core to destination name");
  }

  function _min(uint a, uint b) private pure returns(uint) {
    return a < b ? a : b;
  }

  function _eq(string memory str1, string memory str2) private pure returns(bool) {
    return keccak256(abi.encodePacked(str1)) == keccak256(abi.encodePacked(str2));
  }

  function _notEmpty(string memory str) private pure returns(bool) {
    return bytes(str).length > 0;
  }
}
