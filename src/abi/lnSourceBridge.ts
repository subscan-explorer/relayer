export const lnSourceBridge = [
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
          "internalType": "uint64",
          "name": "providerKey",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "provider",
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
          "internalType": "uint64",
          "name": "providerKey",
          "type": "uint64"
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
          "internalType": "bytes32",
          "name": "transferId",
          "type": "bytes32"
        },
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "providerKey",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "provider",
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
      "name": "Refund",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "indexed": true,
          "internalType": "bytes32",
          "name": "previousAdminRole",
          "type": "bytes32"
        },
        {
          "indexed": true,
          "internalType": "bytes32",
          "name": "newAdminRole",
          "type": "bytes32"
        }
      ],
      "name": "RoleAdminChanged",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "account",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "sender",
          "type": "address"
        }
      ],
      "name": "RoleGranted",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "account",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "sender",
          "type": "address"
        }
      ],
      "name": "RoleRevoked",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "nonce",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "uint64",
          "name": "providerKey",
          "type": "uint64"
        },
        {
          "indexed": false,
          "internalType": "bytes32",
          "name": "transferId",
          "type": "bytes32"
        },
        {
          "indexed": false,
          "internalType": "bytes32",
          "name": "lastBlockHash",
          "type": "bytes32"
        },
        {
          "indexed": false,
          "internalType": "address",
          "name": "localToken",
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
      "inputs": [],
      "name": "DAO_ADMIN_ROLE",
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
      "name": "DEFAULT_ADMIN_ROLE",
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
      "name": "OPERATOR_ROLE",
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
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        }
      ],
      "name": "getRoleAdmin",
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
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "uint256",
          "name": "index",
          "type": "uint256"
        }
      ],
      "name": "getRoleMember",
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
          "name": "role",
          "type": "bytes32"
        }
      ],
      "name": "getRoleMemberCount",
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
              "internalType": "uint64",
              "name": "providerKey",
              "type": "uint64"
            },
            {
              "internalType": "bytes32",
              "name": "previousTransferId",
              "type": "bytes32"
            },
            {
              "internalType": "bytes32",
              "name": "lastBlockHash",
              "type": "bytes32"
            },
            {
              "internalType": "uint112",
              "name": "amount",
              "type": "uint112"
            },
            {
              "internalType": "uint64",
              "name": "nonce",
              "type": "uint64"
            },
            {
              "internalType": "uint64",
              "name": "timestamp",
              "type": "uint64"
            },
            {
              "internalType": "address",
              "name": "token",
              "type": "address"
            },
            {
              "internalType": "address",
              "name": "receiver",
              "type": "address"
            }
          ],
          "internalType": "struct LnBridgeHelper.TransferParameter",
          "name": "param",
          "type": "tuple"
        }
      ],
      "name": "getTransferId",
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
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "grantRole",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "hasRole",
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
      "inputs": [
        {
          "internalType": "address",
          "name": "dao",
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
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "lnProviderIndexes",
      "outputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "lnProviderSize",
      "outputs": [
        {
          "internalType": "uint32",
          "name": "",
          "type": "uint32"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "",
          "type": "uint64"
        }
      ],
      "name": "lnProviders",
      "outputs": [
        {
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
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
          "internalType": "struct LnBridgeSource.LnProviderConfigure",
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
          "internalType": "uint64",
          "name": "providerKey",
          "type": "uint64"
        },
        {
          "internalType": "uint112",
          "name": "amountWithFeeAndPenalty",
          "type": "uint112"
        },
        {
          "internalType": "uint64",
          "name": "nonce",
          "type": "uint64"
        },
        {
          "internalType": "bool",
          "name": "hasRefund",
          "type": "bool"
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
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "latestSlashTransferId",
          "type": "bytes32"
        },
        {
          "internalType": "bytes32",
          "name": "transferId",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "slasher",
          "type": "address"
        }
      ],
      "name": "refund",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint32",
          "name": "tokenIndex",
          "type": "uint32"
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
      "name": "registerOrUpdateLnProvider",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "local",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "remote",
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
          "name": "localDecimals",
          "type": "uint8"
        },
        {
          "internalType": "uint8",
          "name": "remoteDecimals",
          "type": "uint8"
        }
      ],
      "name": "registerToken",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "remoteBridge",
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
      "name": "remoteBridgeAlias",
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
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "renounceRole",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "role",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "account",
          "type": "address"
        }
      ],
      "name": "revokeRole",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_remoteBridge",
          "type": "address"
        }
      ],
      "name": "setRemoteBridge",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "_remoteBridgeAlias",
          "type": "address"
        }
      ],
      "name": "setRemoteBridgeAlias",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes4",
          "name": "interfaceId",
          "type": "bytes4"
        }
      ],
      "name": "supportsInterface",
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
      "name": "tokenLength",
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
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "tokens",
      "outputs": [
        {
          "internalType": "address",
          "name": "localToken",
          "type": "address"
        },
        {
          "internalType": "address",
          "name": "remoteToken",
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
          "name": "localDecimals",
          "type": "uint8"
        },
        {
          "internalType": "uint8",
          "name": "remoteDecimals",
          "type": "uint8"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "uint64",
          "name": "providerKey",
          "type": "uint64"
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
              "internalType": "uint64",
              "name": "providerKey",
              "type": "uint64"
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
          "internalType": "struct LnBridgeSource.Snapshot",
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
          "internalType": "uint32",
          "name": "_tokenIndex",
          "type": "uint32"
        },
        {
          "internalType": "uint112",
          "name": "_protocolFee",
          "type": "uint112"
        }
      ],
      "name": "updateProtocolFee",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "bytes32",
          "name": "latestSlashTransferId",
          "type": "bytes32"
        },
        {
          "internalType": "bytes32",
          "name": "lastTransferId",
          "type": "bytes32"
        },
        {
          "internalType": "address",
          "name": "provider",
          "type": "address"
        },
        {
          "internalType": "uint112",
          "name": "amount",
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
]
