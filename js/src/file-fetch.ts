import { GIT_COMMIT_HASH } from './config'
import { FileFetch } from './types'

const DEFAULT_REMOTE_BASE_URL = `https://github.com/reclaimprotocol/zk-symmetric-crypto/raw/${GIT_COMMIT_HASH}/resources/`
const DEFAULT_BASE_PATH = '../resources'

export type MakeRemoteFileFetchOpts = {
	baseUrl?: string
}

export type MakeLocalFileFetchOpts = {
	basePath?: string
}

/**
 * Fetches ZK resources from a remote server.
 * Assumes the structure of the resources is:
 * BASE_URL/{engine}/{filename}
 *
 * By default, it uses the resources from a specific commit
 * of the `zk-symmetric-crypto` repository.
 */
export function makeRemoteFileFetch({
	baseUrl = DEFAULT_REMOTE_BASE_URL,
}: MakeRemoteFileFetchOpts = {}): FileFetch {
	return {
		async fetch(engine, filename) {
			const url = `${baseUrl}/${engine}/${filename}`
			const res = await fetch(url)
			if(!res.ok) {
				throw new Error(
					`${engine}-${filename} fetch failed with code: ${res.status}`
				)
			}

			const arr = await res.arrayBuffer()
			return new Uint8Array(arr)
		},
	}
}

/**
 * Fetches ZK resources from the local file system.
 * Assumes the structure of the resources is:
 * BASE_PATH/{engine}/{filename}
 */
export function makeLocalFileFetch(
	{ basePath = DEFAULT_BASE_PATH }: MakeLocalFileFetchOpts = {}
): FileFetch {
	return {
		async fetch(engine, filename) {
			const path = `${basePath}/${engine}/${filename}`
			// import here to avoid loading fs in
			// a browser env
			const { readFile } = await import('fs/promises')
			const { join } = await import('path')
			const fullPath = join(__dirname, path)
			const buff = await readFile(fullPath)
			return buff
		},
	}
}