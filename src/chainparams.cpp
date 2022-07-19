// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Scholarship Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h" 
#include "arith_uint256.h"

using namespace std;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.nTime = nTime;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0  << CScriptNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "23/06/2022 - This is Scholarship Coin";
    const CScript genesisOutputScript = CScript() << ParseHex("04b638831e30c9ad9c7df462f7677ca8740d7cac3723f692932bed42c7070f1756e42743b000c6150d3a54b320d36af56d93f00ef5897c41c62028bbeb82011a53") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}


/*** M A I N   N E T W O R K ***/

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nMaxReorganizationDepth = 500;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimitV2 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan =  10 * 60;
        consensus.nTargetSpacingV1 = 3 * 60;
        consensus.nTargetSpacing = 3 * 60;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 5;
        consensus.nMinerConfirmationWindow = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        consensus.nProtocolV1RetargetingFixedTime = 1655995846;
        consensus.nProtocolV2Time = 1655995847;
        consensus.nProtocolV3Time = 1655995848;
        consensus.nLastPOWBlock = 1200000;
        consensus.nStakeTimestampMask = 0xf;
        consensus.nCoinbaseMaturity = 50; 
        consensus.nStakeMinAge = 6 * 60 * 60;

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100001");

        pchMessageStart[0] = 0xb5;
        pchMessageStart[1] = 0x3d;
        pchMessageStart[2] = 0x80;
        pchMessageStart[3] = 0x00;
        nDefaultPort = 55348;
        nPruneAfterHeight = 100000;


        genesis = CreateGenesisBlock(1655995846, 222052, 0x1e0ffff0, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
 
        assert(consensus.hashGenesisBlock == uint256S("0x00000740c3ab3ef407b5667e039e3bb4d0f733a306e7b09b0bd28dd23948a5e3"));
        assert(genesis.hashMerkleRoot == uint256S("0xb93661ffa5d22907d8f59ebe3400498e35f0461c6dc6ab97d21e5a2492000cea"));

        vSeeds.push_back(CDNSSeedData("seed.scholarshipcoin.org", "node.scholarshipcoin.org"));
        vSeeds.push_back(CDNSSeedData("seed2.scholarshipcoin.org", "node2.scholarshipcoin.org"));
        vSeeds.push_back(CDNSSeedData("explorer.scholarshipcoin.org", "pool.scholarshipcoin.org"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63); // S
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,28); // C
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,52); // M & N
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        cashaddrPrefix = "Scholarship";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
                    boost::assign::map_list_of
                    (0, uint256S("0x00000740c3ab3ef407b5667e039e3bb4d0f733a306e7b09b0bd28dd23948a5e3")),				
                    1655995846, // * UNIX timestamp of last checkpoint block
                    0,    // * total number of transactions between genesis and last checkpoint
                                //   (the tx=... number in the SetBestChain debug.log lines)
                    0      // * estimated number of transactions per day after checkpoint
        };
   }
};
static CMainParams mainParams;


/*** T E S T N E T ***/

class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nMaxReorganizationDepth = 500;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimitV2 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan =  10 * 60;
        consensus.nTargetSpacingV1 = 60;
        consensus.nTargetSpacing = 60;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512;
        consensus.nMinerConfirmationWindow = 5;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        consensus.nProtocolV1RetargetingFixedTime = 1655996103;
        consensus.nProtocolV2Time = 1655996104;
        consensus.nProtocolV3Time = 1655996105;
        consensus.nLastPOWBlock = 100000;
        consensus.nStakeTimestampMask = 0xf;
        consensus.nCoinbaseMaturity = 10; 
        consensus.nStakeMinAge = 8 * 60 * 60;

        pchMessageStart[0] = 0x42; 
        pchMessageStart[1] = 0x56;
        pchMessageStart[2] = 0xb1;
        pchMessageStart[3] = 0x41;
        nDefaultPort = 35353;

        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000000000000100001");

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1655996103, 1322056, 0x1e0ffff0, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000006917e0cfbe8f8639b5b81040872c1f38670a52928b749b105793688456e"));
        assert(genesis.hashMerkleRoot == uint256S("0x25d800a99a2d7374395f4175775276cdb4dc8b94d68c68297f050813fc1e73e1"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,128); // t
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,65); // T
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,111); // m & n
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        cashaddrPrefix = "schotest";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x000006917e0cfbe8f8639b5b81040872c1f38670a52928b749b105793688456e")),
            1655996103,
            0,
            0
        };
    }
};
static CTestNetParams testNetParams;


/*** R E G R E S S I O N   T E S T ***/

class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nMaxReorganizationDepth = 50;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimitV2 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan =  10 * 60;
        consensus.nTargetSpacingV1 = 2 * 64;
        consensus.nTargetSpacing = 2 * 60;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108;
        consensus.nMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        consensus.nProtocolV1RetargetingFixedTime = 1655996180;
        consensus.nProtocolV2Time = 1655996181;
        consensus.nProtocolV3Time = 1655996182;
        consensus.nLastPOWBlock = 250;
        consensus.nStakeTimestampMask = 0xf;
        consensus.nCoinbaseMaturity = 3; 
        consensus.nStakeMinAge = 1 * 60 * 60;

        pchMessageStart[0] = 0x3d;
        pchMessageStart[1] = 0x80;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0x06;
        nDefaultPort = 45454;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1655996180, 2963963, 0x1e0ffff0, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
 
 
        assert(consensus.hashGenesisBlock == uint256S("0x000000a5335ccb6d52d8ae350a006844c2a2f9377e63811a7c44484205c1c2c1"));
        assert(genesis.hashMerkleRoot == uint256S("0x00ffc8b1cc829ada59b3dbde99248d87feb0cc0eb2516ae7c9bc0c33ce74e3b8"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,122); // r
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,60); // R 
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,126); // s & t
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        cashaddrPrefix = "schoreg";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}


