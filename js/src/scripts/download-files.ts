import { createReadStream, createWriteStream } from 'fs'
import { mkdir, rename, rm } from 'fs/promises'
import { dirname, join } from 'path'
import { Readable } from 'stream'
import { pipeline } from 'stream/promises'
import { Extract } from 'unzipper'
import { GIT_COMMIT_HASH } from '../config.ts'
import type { Logger } from '../types.ts'


const logger: Logger = console

const ZIP_URL = `https://github.com/reclaimprotocol/zk-symmetric-crypto/archive/${GIT_COMMIT_HASH}.zip`
const DOWNLOAD_DIR = './zk-symmetric-crypto-download'
const EXTRACTED_DIR = `./zk-symmetric-crypto-${GIT_COMMIT_HASH}`

const __dirname = dirname(import.meta.url.replace('file://', ''))
const BASE_DIR = join(__dirname, '../../')
const DIRS_TO_COPY = [
	'resources',
	'bin'
]

async function downloadAndExtractZip() {
	logger.info(`downloading archive from ${ZIP_URL}`)

	const response = await fetch(ZIP_URL)
	if(!response.ok) {
		throw new Error(`Failed to download: ${response.status} ${response.statusText}`)
	}

	const zipPath = join(DOWNLOAD_DIR, 'repo.zip')
	await rm(DOWNLOAD_DIR, { recursive: true, force: true })
	await rm(EXTRACTED_DIR, { recursive: true, force: true })

	// Create download directory and download ZIP
	await mkdir(DOWNLOAD_DIR, { recursive: true })

	if(!response.body) {
		throw new Error('Response body is null')
	}

	await pipeline(
		// @ts-ignore
		Readable.from(response.body),
		createWriteStream(zipPath)
	)

	logger.info('downloaded ZIP, extracting...')

	// Extract ZIP
	await pipeline(
		createReadStream(zipPath),
		Extract({ path: './' })
	)

	logger.info(`extracted to ${EXTRACTED_DIR}`)
}

async function main() {
	for(const dir of DIRS_TO_COPY) {
		await rm(join(BASE_DIR, dir), { recursive: true, force: true })
		logger.info(`removing old "${dir}" directory`)
	}

	await downloadAndExtractZip()

	for(const dir of DIRS_TO_COPY) {
		await rename(join(EXTRACTED_DIR, dir), join(BASE_DIR, dir))
		logger.info(`moved "${dir}" directory`)
	}

	// Clean up
	await rm(DOWNLOAD_DIR, { recursive: true, force: true })
	await rm(EXTRACTED_DIR, { recursive: true, force: true })
	logger.info('cleaned up temporary files')

	logger.info('done')
}

main()