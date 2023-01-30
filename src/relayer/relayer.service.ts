import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { TasksService } from '../tasks/tasks.service';
import { Store } from '../base/store';
import { Erc20Contract, LpSub2SubBridgeContract, RelayArgs } from "../base/contract";
import { EtherBigNumber } from '../base/bignumber';
import { EthereumProvider, TransactionInfo, scaleBigger } from "../base/provider";
import { EthereumConnectedWallet } from "../base/wallet";
import { DataworkerService } from "../dataworker/dataworker.service";
import { ConfigureService } from '../configure/configure.service';
import { PriceOracle } from "../base/oracle";

export class ChainInfo {
    chainName: string;
    rpc: string;
    native: string;
    provider: EthereumProvider;
}

export class BridgeConnectInfo {
    chainInfo: ChainInfo;
    bridge: LpSub2SubBridgeContract;
}

export class FromToken {
    fromAddress: string;
    feeTokenAddress: string;
    chainInfo: ChainInfo;
}

export class TokenInfo {
    toAddress: string;
    fromTokens: FromToken[];
}

export class LpBridges {
    isProcessing: boolean;
    toBridge: BridgeConnectInfo;
    tokens: TokenInfo[];
    priceOracle: PriceOracle.TokenPriceOracle;
    relayerGasFeeToken: string;
}

@Injectable()
export class RelayerService implements OnModuleInit {
    private readonly logger = new Logger('relayer');
    private readonly scheduleInterval = 10000;
    private chainInfos = new Map;
    private lpBridges: LpBridges[];
    public store: Store;

    constructor(
        protected taskService: TasksService,
        protected dataworkerService: DataworkerService,
        protected configureService: ConfigureService,
    ) {
        this.chainInfos = new Map(this.configureService.config.chains.map((config) => {
            return [config.name, {
                chainName: config.name,
                rpc: config.rpc,
                native: config.native,
                provider: new EthereumProvider(config.rpc)
            }];
        }));
        this.lpBridges = this.configureService.config.bridges.map((config) => {
            let toChainInfo = this.chainInfos.get(config.toChain);
            if (!toChainInfo) {
                this.logger.error(`to chain is not configured ${config.toChain}`);
                return null;
            }
            let wallet = new EthereumConnectedWallet(config.privateKey, toChainInfo.provider);
            let bridge = new LpSub2SubBridgeContract(config.bridgeAddress, wallet.wallet);
            let toConnectInfo = {
                chainInfo: toChainInfo,
                bridge
            };
            let tokens = config.tokens.map((fromBridgeConfig) => {
                let fromTokens = fromBridgeConfig.fromAddresses.map((tokenConfig) => {
                    let fromChainInfo = this.chainInfos.get(tokenConfig.chainName);
                    if (!fromChainInfo) {
                        this.logger.error(`from chain is not configured ${tokenConfig.chainName}`);
                        return null;
                    }
                    return {
                        fromAddress: tokenConfig.fromAddress,
                        feeTokenAddress: tokenConfig.feeTokenAddress,
                        chainInfo: fromChainInfo
                    }
                }).filter((item) => item !== null);
                if (fromTokens.length === 0) {
                    return null;
                }
                return {
                    toAddress: fromBridgeConfig.toAddress,
                    fromTokens: fromTokens
                }
            }).filter((item) => item !== null);

            const oracleName = config.priceOracle.name;
            const oracleConfig = config.priceOracle.configure;
            const oracleProvider = this.chainInfos.get(config.priceOracle.chainName)?.provider;
            return {
                isProcessing: false,
                toBridge: toConnectInfo,
                tokens: tokens,
                priceOracle: new (<any>PriceOracle)[oracleName](oracleProvider, oracleConfig),
                relayerGasFeeToken: config.priceOracle.relayerGasFeeToken,
            };
        }).filter((item) => item !== null);
    }

    // the target chain should not be conflict
    async onModuleInit() {
        this.logger.log("relayer service start");
        this.store = new Store(this.configureService.storePath);
        this.lpBridges.forEach((item, index) => {
            this.taskService.addScheduleTask(
                `${item.toBridge.chainInfo.chainName}-lpbridge-relayer`,
                this.scheduleInterval,
                async () => {
                    if (item.isProcessing) {
                        return;
                    }
                    item.isProcessing = true;
                    try {
                        await this.relay(item);
                    } catch (err) {
                        this.logger.warn(`relay bridge failed, err: ${err}`);
                    }
                    item.isProcessing = false;
                }
            );
        });
    }

    async relay(bridge: LpBridges) {
        // checkPending transaction
        const toChainInfo = bridge.toBridge.chainInfo;
        let txHash = await this.store.getPendingTransaction(toChainInfo.chainName);
        let transactionInfo: TransactionInfo | null = null;
        if (txHash) {
            transactionInfo = await toChainInfo.provider.checkPendingTransaction(txHash);
            // may be query error
            if (transactionInfo === null) {
                return;
            }
            // confirmed
            if (transactionInfo.confirmedBlock > 0) {
                if (transactionInfo.confirmedBlock < 8) {
                    this.logger.log(`waiting for relay tx finialize: ${transactionInfo.confirmedBlock}, txHash: ${txHash}`);
                    return;
                } else {
                    // delete in store
                    this.logger.log(`the pending tx is confirmed, txHash: ${txHash}`);
                    await this.store.delPendingTransaction(toChainInfo.chainName);
                    return;
                }
            }
        }

        // relay for each token configured
        for (const token of bridge.tokens) {
            // checkProfit
            const fromChains = token.fromTokens.map((item) => {
                return item.chainInfo.chainName;
            });
            const needRelayRecords = await this.dataworkerService.queryRecordNeedRelay(
                this.configureService.indexer,
                fromChains,
                toChainInfo.chainName,
                token.toAddress,
                10,
                0
            );
            if (needRelayRecords && needRelayRecords.length > 0) {
                for (const record of needRelayRecords) {
                    let fromItem = token.fromTokens.find((fromToken) => {
                        return fromToken.fromAddress === record.sendTokenAddress &&
                               fromToken.chainInfo.chainName === record.fromChain;
                    });

                    const profitable = await this.dataworkerService.checkProfitable(
                        record,
                        bridge.toBridge.bridge,
                        fromItem.chainInfo.provider,
                        toChainInfo.provider,
                        bridge.priceOracle,
                        fromItem.feeTokenAddress,
                        bridge.relayerGasFeeToken,
                    );
                    if (profitable.result) {
                        // replace ?
                        let nonce: number | null = null;
                        if (transactionInfo !== null) {
                            const needReplace = scaleBigger(profitable.gasPrice, transactionInfo.gasPrice, 1.5);
                            if (!needReplace) {
                                return;
                            }
                            nonce = transactionInfo.nonce;
                        }
                        // try relay: check balance and fee enough
                        const chainId = this.dataworkerService.getChainId(record.id);
                        const args: RelayArgs = {
                            messageNonce: (new EtherBigNumber(record.messageNonce)).Number,
                            token: token.toAddress,
                            sender: record.sender,
                            receiver: record.recipient,
                            amount: (new EtherBigNumber(record.sendAmount)).Number,
                            sourceChainId: (new EtherBigNumber(chainId)).Number,
                            issuingNative: toChainInfo.native === record.recvToken,
                        };
                        const relayGasLimit = (new EtherBigNumber(this.configureService.relayGasLimit)).Number;
                        const err = await bridge.toBridge.bridge.tryRelay(args, relayGasLimit);
                        if (err === null) {
                            this.logger.log(`find valid relay info, id: ${record.id}, amount: ${record.sendAmount}, nonce: ${nonce}`);
                            // relay and return
                            const tx = await bridge.toBridge.bridge.relay(args, profitable.gasPrice, nonce, relayGasLimit);
                            // save to store
                            await this.store.savePendingTransaction(toChainInfo.chainName, tx.hash);
                            this.logger.log(`success relay message, txhash: ${tx.hash}`);
                            return;
                        } else {
                            this.logger.warn(`try to relay failed, id: ${record.id}, err ${err}`);
                        }
                    }
                }
            }
        }
    }
}

