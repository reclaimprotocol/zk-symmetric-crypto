import { EncryptionAlgorithm, ZKProofInput } from '../types';
import { NoirWitnessInput } from './types';
/**
 * Convert ZKProofInput to Noir witness format
 * Noir expects byte arrays for AES-256-CTR
 */
export declare function convertToNoirWitness(algorithm: EncryptionAlgorithm, input: ZKProofInput): NoirWitnessInput;
/**
 * Get the circuit filename for the algorithm
 */
export declare function getCircuitFilename(algorithm: EncryptionAlgorithm): string;
