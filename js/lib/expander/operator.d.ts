import { MakeZKOperatorOpts, ZKOperator } from '../types';
export type ExpanderOpts = {
    /**
     * Number of parallel workers to use.
     * Set to 0 to disable parallelism.
     * @default 0
     */
    maxWorkers?: number;
};
export declare function makeExpanderZkOperator({ algorithm, fetcher, options: { maxWorkers } }: MakeZKOperatorOpts<ExpanderOpts>): ZKOperator;
