"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const child_process_1 = require("child_process");
const promises_1 = require("fs/promises");
const path_1 = require("path");
const util_1 = require("util");
const execPromise = (0, util_1.promisify)(child_process_1.exec);
const logger = console;
const GIT_COMMIT_HASH_OF_CIRCUIT = '4cc22d253eb4baa967ced3d99a3d7c9b9d98bbfe';
const CLONE_DIR = './zk-symmetric-crypto';
const CLONE_CMD = [
    `git clone https://github.com/ModoriLabs/zk-symmetric-crypto ${CLONE_DIR}`,
    `cd ${CLONE_DIR}`,
    `git reset ${GIT_COMMIT_HASH_OF_CIRCUIT} --hard`
].join(' && ');
const BASE_DIR = (0, path_1.join)(__dirname, '../../');
const DIRS_TO_COPY = [
    'resources',
    'bin'
];
async function main() {
    for (const dir of DIRS_TO_COPY) {
        await (0, promises_1.rm)((0, path_1.join)(BASE_DIR, dir), { recursive: true, force: true });
        logger.info(`removing old "${dir}" directory`);
    }
    // remove in case it already exists -- we want to clone fresh
    await (0, promises_1.rm)(CLONE_DIR, { recursive: true, force: true });
    logger.info(`removed old cloned "${CLONE_DIR}" directory`);
    logger.info(`cloning repo, #${GIT_COMMIT_HASH_OF_CIRCUIT}. This may take a while...`);
    await execPromise(CLONE_CMD);
    logger.info(`cloned repo to "${CLONE_DIR}"`);
    for (const dir of DIRS_TO_COPY) {
        await (0, promises_1.rename)((0, path_1.join)(CLONE_DIR, dir), (0, path_1.join)(BASE_DIR, dir));
        logger.info(`moved "${dir}" directory`);
    }
    await (0, promises_1.rm)(CLONE_DIR, { recursive: true, force: true });
    logger.info(`removed "${CLONE_DIR}" directory`);
    logger.info('done');
}
main();
