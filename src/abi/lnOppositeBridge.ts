export const lnOppositeBridge = [
     {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint8",
          "name": "version",
          "type": "uint8"
        }
      ],
      "name": "Initialized",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "remoteChainId",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "sourceToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "targetToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint112",
          "name": "amount",
          "type": "uint112"
        }
      ],
      "name": "LiquidityWithdrawn",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "remoteChainId",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "sourceToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "targetToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint112",
          "name": "margin",
          "type": "uint112"
        },
        {
          "indexed": false,
          "internalType": "uint112",
          "name": "baseFee",
          "type": "uint112"
        },
        {
          "indexed": false,
          "internalType": "uint16",
          "name": "liquidityfeeRate",
          "type": "uint16"
        }
      ],
      "name": "LnProviderUpdated",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "Paused",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "remoteChainId",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "bytes32",
          "name": "transferId",
          "type": "bytes32"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "sourceToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "targetToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint112",
          "name": "margin",
          "type": "uint112"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "slasher",
          "type": "address"
        }
      ],
      "name": "Slash",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "remoteChainId",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "sourceToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "targetToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "bytes32",
          "name": "transferId",
          "type": "bytes32"
        }
      ],
      "name": "SlashRequest",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "remoteChainId",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "bytes32",
          "name": "transferId",
          "type": "bytes32"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "sourceToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "targetToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint112",
          "name": "amount",
          "type": "uint112"
        },
        {
          "indexed": false,
          "internalType": "uint112",
          "name": "fee",
          "type": "uint112"
        },
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "timestamp",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "receiver",
          "type": "address"
        }
      ],
      "name": "TokenLocked",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "bytes32",
          "name": "transferId",
          "type": "bytes32"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "slasher",
          "type": "address"
        }
      ],
      "name": "TransferFilled",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "Unpaused",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "remoteChainId",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "sourceToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "targetToken",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint112",
          "name": "amount",
          "type": "uint112"
        }
      ],
      "name": "WithdrawMarginRequest",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "dao",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "name": "fillTransfers",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_dao",
          "type": "address"
        }
      ],
      "name": "initialize",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "name": "lockInfos",
      "outputs": [
        {
          "internalType": "uint112",
          "name": "amountWithFeeAndPenalty",
          "type": "uint112"
        },
        {
          "internalType": "uint32",
          "name": "timestamp",
          "type": "uint32"
        },
        {
          "internalType": "bool",
          "name": "hasSlashed",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "operator",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "pause",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "paused",
      "outputs": [
        {
          "internalType": "bool",
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "protocolFeeReceiver",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "_sourceToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_targetToken",
          "type": "address"
        }
      ],
      "name": "providerPause",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "_sourceToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_targetToken",
          "type": "address"
        }
      ],
      "name": "providerUnpause",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "bytes32",
          "name": "_transferId",
          "type": "bytes32"
        },
        {
          "internalType": "bytes",
          "name": "_extParams",
          "type": "bytes"
        }
      ],
      "name": "requestRetrySlashAndRemoteRelease",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "components": [
            {
              "internalType": "bytes32",
              "name": "previousTransferId",
              "type": "bytes32"
            },
            {
              "internalType": "address",
              "name": "provider",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "sourceToken",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "targetToken",
              "type": "address"
            },
            {
              "internalType": "uint112",
              "name": "amount",
              "type": "uint112"
            },
            {
              "internalType": "uint256",
              "name": "timestamp",
              "type": "uint256"
            },
            {
              "internalType": "address",
              "name": "receiver",
              "type": "address"
            }
          ],
          "internalType": "struct LnBridgeHelper.TransferParameter",
          "name": "_params",
          "type": "tuple"
        },
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "bytes32",
          "name": "_expectedTransferId",
          "type": "bytes32"
        },
        {
          "internalType": "bytes",
          "name": "_extParams",
          "type": "bytes"
        }
      ],
      "name": "requestSlashAndRemoteRelease",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "bytes32",
          "name": "_lastTransferId",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "_sourceToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_targetToken",
          "type": "address"
        },
        {
          "internalType": "uint112",
          "name": "_amount",
          "type": "uint112"
        },
        {
          "internalType": "bytes",
          "name": "_extParams",
          "type": "bytes"
        }
      ],
      "name": "requestWithdrawMargin",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_operator",
          "type": "address"
        }
      ],
      "name": "setOperator",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "_remoteBridge",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_service",
          "type": "address"
        }
      ],
      "name": "setReceiveService",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "_remoteBridge",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_service",
          "type": "address"
        }
      ],
      "name": "setSendService",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "_sourceToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_targetToken",
          "type": "address"
        },
        {
          "internalType": "uint112",
          "name": "_protocolFee",
          "type": "uint112"
        },
        {
          "internalType": "uint112",
          "name": "_penaltyLnCollateral",
          "type": "uint112"
        },
        {
          "internalType": "uint8",
          "name": "_sourceDecimals",
          "type": "uint8"
        },
        {
          "internalType": "uint8",
          "name": "_targetDecimals",
          "type": "uint8"
        }
      ],
      "name": "setTokenInfo",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "_latestSlashTransferId",
          "type": "bytes32"
        },
        {
          "internalType": "bytes32",
          "name": "_transferId",
          "type": "bytes32"
        },
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "_timestamp",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "_sourceToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_targetToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_provider",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_slasher",
          "type": "address"
        }
      ],
      "name": "slash",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "name": "slashInfos",
      "outputs": [
        {
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "sourceToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "targetToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "slasher",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "timestamp",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "name": "srcProviders",
      "outputs": [
        {
          "components": [
            {
              "internalType": "uint112",
              "name": "margin",
              "type": "uint112"
            },
            {
              "internalType": "uint112",
              "name": "baseFee",
              "type": "uint112"
            },
            {
              "internalType": "uint16",
              "name": "liquidityFeeRate",
              "type": "uint16"
            },
            {
              "internalType": "bool",
              "name": "pause",
              "type": "bool"
            }
          ],
          "internalType": "struct LnOppositeBridgeSource.SourceProviderConfigure",
          "name": "config",
          "type": "tuple"
        },
        {
          "internalType": "bytes32",
          "name": "lastTransferId",
          "type": "bytes32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "name": "tokenInfos",
      "outputs": [
        {
          "internalType": "uint112",
          "name": "protocolFee",
          "type": "uint112"
        },
        {
          "internalType": "uint112",
          "name": "penaltyLnCollateral",
          "type": "uint112"
        },
        {
          "internalType": "uint8",
          "name": "sourceDecimals",
          "type": "uint8"
        },
        {
          "internalType": "uint8",
          "name": "targetDecimals",
          "type": "uint8"
        },
        {
          "internalType": "bool",
          "name": "isRegistered",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "_provider",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_sourceToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_targetToken",
          "type": "address"
        },
        {
          "internalType": "uint112",
          "name": "_amount",
          "type": "uint112"
        }
      ],
      "name": "totalFee",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "components": [
            {
              "internalType": "uint256",
              "name": "remoteChainId",
              "type": "uint256"
            },
            {
              "internalType": "address",
              "name": "provider",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "sourceToken",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "targetToken",
              "type": "address"
            },
            {
              "internalType": "bytes32",
              "name": "transferId",
              "type": "bytes32"
            },
            {
              "internalType": "uint112",
              "name": "totalFee",
              "type": "uint112"
            },
            {
              "internalType": "uint112",
              "name": "depositedMargin",
              "type": "uint112"
            }
          ],
          "internalType": "struct LnOppositeBridgeSource.Snapshot",
          "name": "_snapshot",
          "type": "tuple"
        },
        {
          "internalType": "uint112",
          "name": "_amount",
          "type": "uint112"
        },
        {
          "internalType": "address",
          "name": "_receiver",
          "type": "address"
        }
      ],
      "name": "transferAndLockMargin",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "components": [
            {
              "internalType": "bytes32",
              "name": "previousTransferId",
              "type": "bytes32"
            },
            {
              "internalType": "address",
              "name": "provider",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "sourceToken",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "targetToken",
              "type": "address"
            },
            {
              "internalType": "uint112",
              "name": "amount",
              "type": "uint112"
            },
            {
              "internalType": "uint256",
              "name": "timestamp",
              "type": "uint256"
            },
            {
              "internalType": "address",
              "name": "receiver",
              "type": "address"
            }
          ],
          "internalType": "struct LnBridgeHelper.TransferParameter",
          "name": "_params",
          "type": "tuple"
        },
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "bytes32",
          "name": "_expectedTransferId",
          "type": "bytes32"
        }
      ],
      "name": "transferAndReleaseMargin",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_dao",
          "type": "address"
        }
      ],
      "name": "transferOwnership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "unpause",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_receiver",
          "type": "address"
        }
      ],
      "name": "updateFeeReceiver",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "_sourceToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_targetToken",
          "type": "address"
        },
        {
          "internalType": "uint112",
          "name": "_margin",
          "type": "uint112"
        },
        {
          "internalType": "uint112",
          "name": "_baseFee",
          "type": "uint112"
        },
        {
          "internalType": "uint16",
          "name": "_liquidityFeeRate",
          "type": "uint16"
        }
      ],
      "name": "updateProviderFeeAndMargin",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "_latestSlashTransferId",
          "type": "bytes32"
        },
        {
          "internalType": "bytes32",
          "name": "_lastTransferId",
          "type": "bytes32"
        },
        {
          "internalType": "uint256",
          "name": "_remoteChainId",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "_provider",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_sourceToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "_targetToken",
          "type": "address"
        },
        {
          "internalType": "uint112",
          "name": "_amount",
          "type": "uint112"
        }
      ],
      "name": "withdrawMargin",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "stateMutability": "payable",
      "type": "receive"
    }
];
