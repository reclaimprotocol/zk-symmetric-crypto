import { BarretenbergOperator, EncryptionAlgorithm, ZKOperator } from '../index';
export declare function encryptData(algorithm: EncryptionAlgorithm, plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array): Buffer;
export declare function loadCircuit(name: string): any;
type ConfigItem = 'barretenberg' | 'snarkjs' | 'gnark' | 'expander-single-thread' | 'expander-multi-thread';
export declare function getEngineForConfigItem(item: ConfigItem): "snarkjs" | "gnark" | "expander" | "barretenberg";
export declare const ZK_CONFIG_MAP: {
    [E in ConfigItem]: (algorithm: EncryptionAlgorithm) => ZKOperator | BarretenbergOperator;
};
export declare const ZK_CONFIGS: ConfigItem[];
export {};
