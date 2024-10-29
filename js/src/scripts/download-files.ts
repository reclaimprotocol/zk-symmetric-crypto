import { exec } from 'child_process'
import { rename, rm } from 'fs/promises'
import { join } from 'path'
import { promisify } from 'util'
import { GIT_COMMIT_HASH } from '../config'
import { Logger } from '../types'

const execPromise = promisify(exec)

const logger: Logger = console

const CLONE_DIR = './zk-symmetric-crypto'
const CLONE_CMD = [
	`git clone https://github.com/reclaimprotocol/zk-symmetric-crypto ${CLONE_DIR}`,
	`cd ${CLONE_DIR}`,
	`git reset ${GIT_COMMIT_HASH} --hard`
].join(' && ')

const BASE_DIR = join(__dirname, '../../')
const DIRS_TO_COPY = [
	'resources',
	'bin'
]

async function main() {
	for(const dir of DIRS_TO_COPY) {
		await rm(join(BASE_DIR, dir), { recursive: true, force: true })
		logger.info(`removing old "${dir}" directory`)
	}

	// remove in case it already exists -- we want to clone fresh
	await rm(CLONE_DIR, { recursive: true, force: true })
	logger.info(`removed old cloned "${CLONE_DIR}" directory`)

	logger.info(`cloning repo, #${GIT_COMMIT_HASH}. This may take a while...`)

	await execPromise(CLONE_CMD)
	logger.info(`cloned repo to "${CLONE_DIR}"`)

	for(const dir of DIRS_TO_COPY) {
		await rename(join(CLONE_DIR, dir), join(BASE_DIR, dir))
		logger.info(`moved "${dir}" directory`)
	}

	await rm(CLONE_DIR, { recursive: true, force: true })
	logger.info(`removed "${CLONE_DIR}" directory`)

	logger.info('done')
}

main()