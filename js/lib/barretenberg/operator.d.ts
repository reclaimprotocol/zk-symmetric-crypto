import { BarretenbergOperator, MakeZKOperatorOpts } from '../types';
import { BarretenbergOpts } from './types';
/**
 * Creates a Barretenberg ZK operator for Noir circuits
 * This operator uses the UltraHonk proving system from Barretenberg
 */
export declare function makeBarretenbergZKOperator({ algorithm, fetcher, options: { threads } }: MakeZKOperatorOpts<BarretenbergOpts>): BarretenbergOperator;
