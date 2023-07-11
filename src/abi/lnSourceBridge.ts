export const lnSourceBridge = [
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "token",
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
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "token",
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
          "internalType": "uint8",
          "name": "liquidityfeeRate",
          "type": "uint8"
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
          "name": "token",
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
          "internalType": "address",
          "name": "receiver",
          "type": "address"
        }
      ],
      "name": "TokenLocked",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "INIT_SLASH_TRANSFER_ID",
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
      "inputs": [],
      "name": "LIQUIDITY_FEE_RATE_BASE",
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
      "inputs": [],
      "name": "MAX_TRANSFER_AMOUNT",
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
      "inputs": [],
      "name": "feeReceiver",
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
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "token",
          "type": "address"
        }
      ],
      "name": "getProviderKey",
      "outputs": [
        {
          "internalType": "bytes32",
          "name": "",
          "type": "bytes32"
        }
      ],
      "stateMutability": "pure",
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
      "name": "lnProviders",
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
              "internalType": "uint8",
              "name": "liquidityFeeRate",
              "type": "uint8"
            }
          ],
          "internalType": "struct LnOppositeBridgeSource.LnProviderConfigure",
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
      "name": "lockInfos",
      "outputs": [
        {
          "internalType": "uint112",
          "name": "amountWithFeeAndPenalty",
          "type": "uint112"
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
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "name": "tokenInfos",
      "outputs": [
        {
          "internalType": "address",
          "name": "targetToken",
          "type": "address"
        },
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
          "internalType": "uint112",
          "name": "amount",
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
              "internalType": "bytes32",
              "name": "transferId",
              "type": "bytes32"
            },
            {
              "internalType": "uint112",
              "name": "depositedMargin",
              "type": "uint112"
            },
            {
              "internalType": "uint112",
              "name": "totalFee",
              "type": "uint112"
            }
          ],
          "internalType": "struct LnOppositeBridgeSource.Snapshot",
          "name": "snapshot",
          "type": "tuple"
        },
        {
          "internalType": "uint112",
          "name": "amount",
          "type": "uint112"
        },
        {
          "internalType": "address",
          "name": "receiver",
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
          "internalType": "address",
          "name": "sourceToken",
          "type": "address"
        },
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
          "internalType": "uint8",
          "name": "liquidityFeeRate",
          "type": "uint8"
        }
      ],
      "name": "updateProviderFeeAndMargin",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    }
]
