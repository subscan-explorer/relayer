import {
  Wallet,
  providers,
  Contract,
  ContractInterface,
  BigNumber,
  utils,
} from "ethers";
import { TransactionResponse } from "@ethersproject/abstract-provider";
import { erc20 } from "../abi/erc20";
import { lnDefaultBridge } from "../abi/lnDefaultBridge";
import { lnOppositeBridge } from "../abi/lnOppositeBridge";
import { lnv3Bridge } from "../abi/lnv3Bridge";
import { abiSafe } from "../abi/abiSafe";
import { GasPrice } from "../base/provider";

export const zeroAddress: string = "0x0000000000000000000000000000000000000000";
export const zeroTransferId: string =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

export const LNV3_STATUS_LOCKED = 1;

export class EthereumContract {
  protected contract: Contract;
  public address: string;
  constructor(
    address: string,
    abi: ContractInterface,
    signer: Wallet | providers.Provider
  ) {
    this.contract = new Contract(address, abi, signer);
    this.address = address;
  }

  get interface() {
    return this.contract.interface;
  }

  async call(
    method: string,
    args: any,
    gas: GasPrice,
    value: BigNumber | null = null,
    nonce: number | null = null,
    gasLimit: BigNumber | null = null
  ): Promise<TransactionResponse> {
    const gasArgs = gas.isEip1559 ? gas.eip1559fee : gas.fee;
    const txConfig = Object.entries({
      ...gasArgs,
      value,
      nonce,
      gasLimit,
    }).reduce((c, [k, v]) => (v ? ((c[k] = v), c) : c), {});
    return await this.contract[method](...args, txConfig);
  }

  async staticCall(
    method: string,
    args: any,
    value: BigNumber | null = null,
    gasLimit: BigNumber | null = null,
    from: string | null = null
  ): Promise<string> | null {
    try {
      var options = {};
      if (value != null) {
        options = { value: value };
      }
      if (from != null) {
        options[from] = from;
      }
      if (value != null) {
        args = [...args, options];
      }
      await this.contract.callStatic[method](...args);
      return null;
    } catch (error) {
      return error.message;
    }
  }
}

export class Erc20Contract extends EthereumContract {
  constructor(address: string, signer: Wallet | providers.Provider) {
    super(address, erc20, signer);
  }

  // view
  async symbol(): Promise<string> {
    return await this.contract.symbol();
  }

  async name(): Promise<string> {
    return await this.contract.name();
  }

  async decimals(): Promise<number> {
    return await this.contract.decimals();
  }

  async balanceOf(address: string): Promise<BigNumber> {
    return await this.contract.balanceOf(address);
  }

  // call
  async approve(
    address: string,
    amount: BigNumber,
    gas: GasPrice
  ): Promise<TransactionResponse> {
    return this.call("approve", [address, amount], gas, null, null, null);
  }
}

export interface TransferParameter {
  previousTransferId: string;
  relayer: string;
  sourceToken: string;
  targetToken: string;
  amount: BigNumber;
  timestamp: BigNumber;
  receiver: string;
}

export interface RelayArgs {
  transferParameter: TransferParameter;
  remoteChainId: number;
  expectedTransferId: string;
}

export interface TransferParameterV3 {
  remoteChainId: number;
  provider: string;
  sourceToken: string;
  targetToken: string;
  sourceAmount: BigNumber;
  targetAmount: BigNumber;
  receiver: string;
  nonce: BigNumber;
}

export interface RelayArgsV3 {
  transferParameter: TransferParameterV3;
  expectedTransferId: string;
}

export interface LnProviderFeeInfo {
  baseFee: BigNumber;
  liquidityFeeRate: number;
}

export class SafeContract extends EthereumContract {
  constructor(address: string, signer: Wallet | providers.Provider) {
    super(address, abiSafe, signer);
  }

  async tryExecTransaction(
    to: string,
    data: string,
    signatures: string,
    value: BigNumber | null = null
  ): Promise<string> | null {
    return await this.staticCall(
      "execTransaction",
      [to, 0, data, 0, 0, 0, 0, zeroAddress, zeroAddress, signatures],
      value
    );
  }

  async execTransaction(
    to: string,
    data: string,
    signatures: string,
    gas: GasPrice,
    nonce: number | null = null,
    gasLimit: BigNumber | null = null,
    value: BigNumber | null = null
  ): Promise<TransactionResponse> {
    return await this.call(
      "execTransaction",
      [to, 0, data, 0, 0, 0, 0, zeroAddress, zeroAddress, signatures],
      gas,
      value,
      nonce,
      gasLimit
    );
  }
}

export class LnBridgeContract extends EthereumContract {
  private bridgeType: string;
  constructor(
    address: string,
    signer: Wallet | providers.Provider,
    bridgeType: string
  ) {
    if (bridgeType === "default") {
      super(address, lnDefaultBridge, signer);
    } else {
      super(address, lnOppositeBridge, signer);
    }
    this.bridgeType = bridgeType;
  }

  async transferIdExist(transferId: string): Promise<[boolean, any]> {
    const lockInfo = await this.contract.lockInfos(transferId);
    return [lockInfo.timestamp > 0, lockInfo];
  }

  async transferHasFilled(transferId: string): Promise<boolean> {
    const fillInfo = await this.contract.fillTransfers(transferId);
    if (this.bridgeType === "default") {
      return fillInfo.timestamp > 0;
    } else {
      return fillInfo != zeroTransferId;
    }
  }

  async fillTransfers(transferId: string): Promise<any> {
    return await this.contract.fillTransfers(transferId);
  }

  async tryRelay(
    args: RelayArgs | RelayArgsV3,
    gasLimit: BigNumber | null = null
  ): Promise<string> | null {
    const argsV2 = args as RelayArgs;
    var value = null;
    const parameter = argsV2.transferParameter;
    if (parameter.targetToken === zeroAddress) {
      value = parameter.amount;
    }
    return await this.staticCall(
      "transferAndReleaseMargin",
      [
        [
          parameter.previousTransferId,
          parameter.relayer,
          parameter.sourceToken,
          parameter.targetToken,
          parameter.amount,
          parameter.timestamp,
          parameter.receiver,
        ],
        argsV2.remoteChainId,
        argsV2.expectedTransferId,
      ],
      value,
      gasLimit
    );
  }

  relayRawData(args: RelayArgs | RelayArgsV3): string {
    var value = null;
    const argsV2 = args as RelayArgs;
    const parameter = argsV2.transferParameter;
    if (parameter.targetToken === zeroAddress) {
      value = parameter.amount;
    }
    return this.interface.encodeFunctionData("transferAndReleaseMargin", [
      [
        parameter.previousTransferId,
        parameter.relayer,
        parameter.sourceToken,
        parameter.targetToken,
        parameter.amount,
        parameter.timestamp,
        parameter.receiver,
      ],
      argsV2.remoteChainId,
      argsV2.expectedTransferId,
    ]);
  }

  async relay(
    args: RelayArgs | RelayArgsV3,
    gas: GasPrice,
    nonce: number | null = null,
    gasLimit: BigNumber | null = null
  ): Promise<TransactionResponse> {
    var value = null;
    const argsV2 = args as RelayArgs;
    const parameter = argsV2.transferParameter;
    if (parameter.targetToken === zeroAddress) {
      value = parameter.amount;
    }
    return await this.call(
      "transferAndReleaseMargin",
      [
        [
          parameter.previousTransferId,
          parameter.relayer,
          parameter.sourceToken,
          parameter.targetToken,
          parameter.amount,
          parameter.timestamp,
          parameter.receiver,
        ],
        argsV2.remoteChainId,
        argsV2.expectedTransferId,
      ],
      gas,
      value,
      nonce,
      gasLimit
    );
  }
}

export class Lnv3BridgeContract extends EthereumContract {
  constructor(address: string, signer: Wallet | providers.Provider) {
    super(address, lnv3Bridge, signer);
  }

  async transferIdExist(transferId: string): Promise<[boolean, any]> {
    const lockInfo = await this.contract.lockInfos(transferId);
    return [lockInfo.status == LNV3_STATUS_LOCKED, lockInfo];
  }

  async transferHasFilled(transferId: string): Promise<boolean> {
    const fillInfo = await this.contract.fillTransfers(transferId);
    return fillInfo.timestamp > 0;
  }

  async fillTransfers(transferId: string): Promise<any> {
    return await this.contract.fillTransfers(transferId);
  }

  async tryRelay(
    args: RelayArgsV3 | RelayArgs,
    gasLimit: BigNumber | null = null
  ): Promise<string> | null {
    var value = null;
    const argsV3 = args as RelayArgsV3;
    const parameter = argsV3.transferParameter;
    if (parameter.targetToken === zeroAddress) {
      value = parameter.targetAmount;
    }
    return await this.staticCall(
      "relay",
      [
        [
          parameter.remoteChainId,
          parameter.provider,
          parameter.sourceToken,
          parameter.targetToken,
          parameter.sourceAmount,
          parameter.targetAmount,
          parameter.receiver,
          parameter.nonce,
        ],
        argsV3.expectedTransferId,
        true,
      ],
      value,
      gasLimit
    );
  }

  relayRawData(args: RelayArgsV3 | RelayArgs): string {
    var value = null;
    const argsV3 = args as RelayArgsV3;
    const parameter = argsV3.transferParameter;
    if (parameter.targetToken === zeroAddress) {
      value = parameter.targetAmount;
    }
    return this.interface.encodeFunctionData("relay", [
      [
        parameter.remoteChainId,
        parameter.provider,
        parameter.sourceToken,
        parameter.targetToken,
        parameter.sourceAmount,
        parameter.targetAmount,
        parameter.receiver,
        parameter.nonce,
      ],
      argsV3.expectedTransferId,
      true,
    ]);
  }

  async relay(
    args: RelayArgsV3 | RelayArgs,
    gas: GasPrice,
    nonce: number | null = null,
    gasLimit: BigNumber | null = null
  ): Promise<TransactionResponse> {
    var value = null;
    const argsV3 = args as RelayArgsV3;
    const parameter = argsV3.transferParameter;
    if (parameter.targetToken === zeroAddress) {
      value = parameter.targetAmount;
    }
    return await this.call(
      "relay",
      [
        [
          parameter.remoteChainId,
          parameter.provider,
          parameter.sourceToken,
          parameter.targetToken,
          parameter.sourceAmount,
          parameter.targetAmount,
          parameter.receiver,
          parameter.nonce,
        ],
        argsV3.expectedTransferId,
        true,
      ],
      gas,
      value,
      nonce,
      gasLimit
    );
  }
}
