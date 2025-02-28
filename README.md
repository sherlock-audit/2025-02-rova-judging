# Issue M-1: `maxTokenAmountPerUser` limit can be bypassed when currency token has less decimals than the launch token. 

Source: https://github.com/sherlock-audit/2025-02-rova-judging/issues/231 

## Found by 
056Security, 0x15, 0xAlipede, 0xAsen, 0xDemon, 0xMosh, 0xShahilHussain, 0xYjs, 0xbakeng, 0xeix, 0xiehnnkta, 0xlookman, 0xmujahid002, 0xnegan, 0xnolo, 0xpetern, 0xpranav, 10ap17, 1nc0gn170, Aamirusmani1552, Adotsam, Albort, BZ, Bbash, Bigsam, BusinessShotgun, CL001, Chain-sentry, D4n13l, DenTonylifer, DharkArtz, Elawdie, Fiifi, Flare, Harry\_cryptodev, Harsh, Josh4324, Kirkeelee, Limbooo, PASCAL, POB, Praise03, Pro\_King, Ragnarok, SarveshLimaye, Saurabh\_Singh, SlayerSecurity, Waydou, X0sauce, Z-Bra, ZoA, ami, coffiasd, covey0x07, denzi\_, destiny\_rs, dgnnn, dobrevaleri, durov, eLSeR17, godwinudo, heeze, imkapadia, justAWanderKid, klaus, leopoldflint, marouen, merlinboii, oct0pwn, oxelmiguel, oxwhite, phoenixv110, pkabhi01, rekxor, s0x0mtee, sakibcy, smbv-1923, surenyan-oks, t0x1c, techOptimizor, tjudz, tobi0x18, tusharr1411, udo, w33kEd, web3canai, whitestrong, x0rc1ph3r, yuza101, zaiont, zatoichi0826

### Summary

Due to the incorrect comparison in the function `updateParticipation`, an attacker can bypass the `maxTokenAmountPerUser` limit, allowing them to allocate more tokens than allowed.

### Root Cause

The `updateParticipation` function in the `Launch.sol` contract contains a critical vulnerability due to the incorrect comparison of `userTokenAmount` and `additionalCurrencyAmount` (and `refundCurrencyAmount`). This comparison can lead to incorrect calculations when the payment currency and the token have different decimal places. For example, USDC has 6 decimals, while a LaunchToken might have 18 decimals. Adding these values directly without proper normalization can result in incorrect calculations, allowing an attacker to allocate more tokens than the `maxTokenAmountPerUser`.

https://github.com/sherlock-audit/2025-02-rova/blob/main/rova-contracts/src/Launch.sol#L355-L368

### Internal Pre-conditions

Using tokens with less decimals than the token being launched.

### External Pre-conditions

Attacker needs to pass checks for the launch before being able to participate.

### Attack Path

An attacker can exploit this vulnerability by:

1. Initiating a participation with a small amount of tokens.
2. Using the `updateParticipation` function to bypass the `maxTokenAmountPerUser` check due to the issue described above. 


### Impact

An attacker can bypass the `maxTokenAmountPerUser` limit, allowing them to allocate more tokens than allowed. This can lead to an unfair distribution of tokens and financial loss for other participants.
### PoC

_No response_

### Mitigation

Do the comparisons with  `request.tokenAmount` .

# Issue M-2: `userTokens` accounting in `Launch.sol::updateParticipation` is updated incorrectly and can lead to loss of user funds, DOS and a broken invariant 

Source: https://github.com/sherlock-audit/2025-02-rova-judging/issues/312 

## Found by 
0rpse, 0xbakeng, 0xc0ffEE, 10ap17, Boy2000, IvanFitro, John44, KlosMitSoss, Limbooo, SammyOne, X0sauce, ZdravkoHr., farismaulana, rokinot, zzykxx

### Summary

When a user reduces their participation tokens in the launch group sale,`userTokens` in the `_userTokensByLaunchGroup` mapping is updated incorrectly which can lead to loss of user funds for any user trying to claim a refund, this vulnerability can lead to other undesireble behaviours such as users being constantly DOS'd when they try to cancel participation.

### Root Cause

In [`Launch.sol:312`](https://github.com/sherlock-audit/2025-02-rova/blob/main/rova-contracts/src/Launch.sol#L312-L397) when a user reduces their stake in the participation, after the if statement block passes, the userTokens mapping value is incorrectly updated by subtracting `refundCurrencyAmount` from `userTokenAmount` which is grossly incorrect, see below:

```solidity
// Update total tokens requested for user for launch group
userTokens.set(request.userId, userTokenAmount - refundCurrencyAmount);
```

It should be the difference between the current requested token amount and the previous token amount, i.e (userTokens.set(request.userId, userTokenAmount - (prevInfo.tokenAmount - request.tokenAmount));

This error can lead to a number of different undesirable outcomes and this report will explore the outcome of stuck funds when user tries to claim refund.

### Internal Pre-conditions

1. For the token on sale to have the same decimal precision as one of the accepted payment currencies, such as the ERC20 Move token.

### External Pre-conditions

N/A

### Vulnerability Path

Scenario: Let us assume the price of 1 token is 1.5 MOVE which also has 8 decimals and the token on sale also has 8 decimal precision.

Path 1:

1. User creates a participation requesting the max amount of tokens allowed for a user, lets assume 10k tokens costing 15k MOVE.
2. User tries to reduce their requested tokens by half, i.e (10000 * 10^8) -> (5000 * 10^8) Tokens, the refund is calculated coming up to 7.5k MOVE.
3. The update would go like so -> (10000 * 10^8) - (7500 * 10^8) = (2500 * 10^8), which updates `userTokens` incorrectly assigning the user with half the amount of tokens they are supposed to be left with in the mapping storage that tracks their total Tokens in the launch group, although `newInfo.tokenAmount = request.tokenAmount;` would be updated correctly this creates a number of undesirable outcomes depending on what a user does next.

Path 2:

1. The user decides to cancel participation for whatever reason, which then code runs into an underflow here:

```solidity
} else {
           // Subtract cancelled participation token amount from total tokens requested for user
           userTokens.set(request.userId, userTokenAmount - info.tokenAmount);
       }
```

The leaves the user unable to cancel the participation and get back their funded payment currency.

### Impact

As users do not have much control for how the sales turn out, in a scenario where a user is issued a refund, when they try to claim their refund, `processRefund()` would underflow due to this part of the code in the function `userTokens.set(info.userId, userTokenAmount - info.tokenAmount);` as `info.tokenAmount would have a higher amount stored than `userTokenAmount` retrieved from `userTokens`, thus causing locked userfunds for users trying to claim refunds. This is a significant impact being caused by this error that can trickle down to other key functions in this contract such as users being DOS'd when trying to cancel participation in other instances.

### PoC

See vulnerability path.

### Mitigation

Use the correct value/variable which should be the difference between the previous tokenAmount and the new requested tokenAmount.

```diff
- userTokens.set(request.userId, userTokenAmount - refundCurrencyAmount);
+ uint256 tokenDelta = prevInfo.tokenAmount - request.tokenAmount;
+ (userTokens.set(request.userId, userTokenAmount - tokenDelta);
```

