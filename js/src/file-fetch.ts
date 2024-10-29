import { FileFetch, ZKEngine } from "./types"

const DEFAULT_BASE_PATH = '../resources'

export type MakeLocalFileFetchOpts = {
	engine: ZKEngine
	basePath?: string
}

/**
 * Fetches ZK resources from the local file system.
 * Assumes the structure of the resources is:
 * BASE_PATH/{engine}/{filename}
 */
export function makeLocalFileFetch(
	{ engine, basePath = DEFAULT_BASE_PATH }: MakeLocalFileFetchOpts
): FileFetch {
	return {
		async fetch(filename) {
			const path = `${basePath}/${engine}/${filename}`
			// import here to avoid loading fs in
			// a browser env
			const { readFile } = await import('fs/promises')
			const buff = await readFile(path)
			return buff
		},
	}
}