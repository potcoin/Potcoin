// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2015 The Cheebacoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef PPCOIN_KERNEL_H
#define PPCOIN_KERNEL_H

#include "main.h"

// MODIFIER_INTERVAL: time to elapse before new modifier is computed
extern unsigned int nModifierInterval;

// MODIFIER_INTERVAL_RATIO:
// ratio of group interval length between the last group and the first group
static const int MODIFIER_INTERVAL_RATIO = 3;

// Compute the hash modifier for proof-of-stake
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64& nStakeModifier, bool& fGeneratedStakeModifier);

// Check whether stake kernel meets hash target
// Sets hashProofOfStake on success return
bool CheckStakeKernelHash(unsigned int nBits, const CBlock& blockFrom, unsigned int nTxPrevOffset, const CTransaction& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, uint256& targetProofOfStake, bool fPrintProofOfStake=false);

// Check kernel hash target and coinstake signature
// Sets hashProofOfStake on success return
bool CheckProofOfStake(const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake, uint256& targetProofOfStake);

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64 nTimeBlock, int64 nTimeTx);

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex);

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, uint64 nStakeModifierChecksum);

// Get time weight using supplied timestamps
int64 GetCoinAgeWeight(int64 nIntervalBeginning, int64 nIntervalEnd);

#endif // PPCOIN_KERNEL_H
