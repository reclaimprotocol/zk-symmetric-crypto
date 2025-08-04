import { FileFetch } from './types';
export type MakeRemoteFileFetchOpts = {
    baseUrl?: string;
};
export type MakeLocalFileFetchOpts = {
    basePath?: string;
};
/**
 * Fetches ZK resources from a remote server.
 * Assumes the structure of the resources is:
 * BASE_URL/{engine}/{filename}
 *
 * By default, it uses the resources from a specific commit
 * of the `zk-symmetric-crypto` repository.
 */
export declare function makeRemoteFileFetch({ baseUrl, }?: MakeRemoteFileFetchOpts): FileFetch;
/**
 * Fetches ZK resources from the local file system.
 * Assumes the structure of the resources is:
 * BASE_PATH/{engine}/{filename}
 */
export declare function makeLocalFileFetch({ basePath }?: MakeLocalFileFetchOpts): FileFetch;
