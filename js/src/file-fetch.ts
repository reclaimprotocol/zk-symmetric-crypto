import { GIT_COMMIT_HASH } from './config.ts'
import type { FileFetch, Logger } from './types.ts'

const DEFAULT_REMOTE_BASE_URL = `https://github.com/reclaimprotocol/zk-symmetric-crypto/raw/${GIT_COMMIT_HASH}/resources/`
const DEFAULT_BASE_PATH = '../resources'

export type MakeRemoteFileFetchOpts = {
	baseUrl?: string
	maxRetries?: number
	logger?: Logger
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
	maxRetries = 3,
	logger
}: MakeRemoteFileFetchOpts = {}): FileFetch {
	return {
		async fetch(engine, filename) {
			const url = `${baseUrl}/${engine}/${filename}`
			let lastError: unknown

			for(let attempt = 1; attempt <= maxRetries; attempt++) {
				try {
					const res = await fetch(url)
					if(!res.ok) {
						throw new Error(
							`${engine}-${filename} fetch failed with code: ${res.status}`
						)
					}

					const arr = await res.arrayBuffer()
					return new Uint8Array(arr)
				} catch(err) {
					logger?.warn(
						{ err, attempt, engine, filename },
						'failed to fetch zk resource'
					)
					lastError = err
					if(attempt < maxRetries) {
						// add some delay before retrying
						await new Promise(resolve => setTimeout(resolve, 1000 * attempt))
					}
				}
			}

			throw lastError || new Error(
				`Failed to fetch ${engine}-${filename} after ${maxRetries} attempts`
			)
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
			const { join, dirname } = await import('path')
			const __dirname = dirname(import.meta.url.replace('file://', ''))
			const fullPath = join(__dirname, path)
			const buff = await readFile(fullPath)
			return buff
		},
	}
}
