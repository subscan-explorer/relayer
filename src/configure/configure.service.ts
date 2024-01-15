import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as fs from "fs";

export interface ChainConfigInfo {
  name: string;
  rpc: string;
  native: string;
  chainId: number;
  fixedGasPrice: number;
  notSupport1559: boolean;
}

export interface ProviderInfo {
  fromAddress: string;
  toAddress: string;
  swapRate: number;
}

export interface BridgeConfigInfo {
  fromChain: string;
  toChain: string;
  sourceBridgeAddress: string;
  targetBridgeAddress: string;
  encryptedPrivateKey: string;
  // signer: signer the transaction
  // executer: signer & execute transaction
  // undefined: not safe wallet
  safeWalletAddress: string | undefined;
  safeWalletUrl: string | undefined;
  safeWalletRole: string | undefined;
  minProfit: number;
  maxProfit: number;
  feeLimit: number;
  reorgThreshold: number;
  bridgeType: string;
  providers: ProviderInfo[];
}

export interface ConfigInfo {
  indexer: string;
  relayGasLimit: number;
  chains: ChainConfigInfo[];
  bridges: BridgeConfigInfo[];
}

@Injectable()
export class ConfigureService {
  private readonly configPath =
    this.configService.get<string>("LP_BRIDGE_PATH");
  public readonly storePath = this.configService.get<string>(
    "LP_BRIDGE_STORE_PATH"
  );
  public readonly config: ConfigInfo = JSON.parse(
    fs.readFileSync(this.configPath, "utf8")
  );
  constructor(private configService: ConfigService) {}
}
