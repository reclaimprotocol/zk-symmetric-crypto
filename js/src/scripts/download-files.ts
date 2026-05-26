import { spawn } from 'child_process'
import { createWriteStream } from 'fs'
import { mkdir, rename, rm } from 'fs/promises'
import { dirname, join } from 'path'
import { Readable } from 'stream'
import { pipeline } from 'stream/promises'
import { fileURLToPath } from 'url'
import { GIT_COMMIT_HASH } from '../config.ts'
import type { Logger } from '../types.ts'

const logger: Logger = console

const ZIP_URL = `https://github.com/reclaimprotocol/zk-symmetric-crypto/archive/${GIT_COMMIT_HASH}.zip`
const DOWNLOAD_DIR = './zk-symmetric-crypto-download'
const EXTRACTED_DIR = `./zk-symmetric-crypto-${GIT_COMMIT_HASH}`

// fileURLToPath handles the Windows file:///F:/... -> F:\... conversion;
// stripping the `file://` prefix by hand leaves a leading slash that breaks fs ops.
const __dirname = dirname(fileURLToPath(import.meta.url))
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

	await extractZip(zipPath, './')

	logger.info(`extracted to ${EXTRACTED_DIR}`)
}

async function extractZip(zipFile: string, destDir: string) {
	// Windows ships PowerShell but not `unzip`; everywhere else, `unzip` is the
	// safe assumption. Using spawn (not exec) so paths with spaces stay intact.
	if(process.platform === 'win32') {
		await runCmd('powershell', [
			'-NoProfile',
			'-ExecutionPolicy', 'Bypass',
			'-Command',
			`Expand-Archive -LiteralPath '${zipFile}' -DestinationPath '${destDir}' -Force`,
		])
	} else {
		await runCmd('unzip', ['-q', zipFile, '-d', destDir])
	}
}

function runCmd(cmd: string, args: string[]) {
	return new Promise<void>((resolve, reject) => {
		const child = spawn(cmd, args, { stdio: 'inherit' })
		child.on('error', reject)
		child.on('exit', code => (
			code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}`))
		))
	})
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