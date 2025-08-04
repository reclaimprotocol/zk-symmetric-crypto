"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// script to publish the package to NPM.
// Will automatically increment the semver if the
// current version is already published. Not recommended
// if the commit has breaking changes.
const child_process_1 = require("child_process");
const compare_versions_1 = require("compare-versions");
const promises_1 = require("fs/promises");
const util_1 = require("util");
const logger = console;
const execPromise = (0, util_1.promisify)(child_process_1.exec);
async function main() {
    const PKG = await readPackageJson();
    const npmVersion = await getNpmVersion().catch(err => {
        if (err.stderr?.includes('E404')) {
            return undefined;
        }
        throw err;
    });
    let pkgVersion = PKG.version;
    logger.info(`Current version: ${PKG.version}, NPM version: ${npmVersion || '-'}`);
    if (npmVersion && (0, compare_versions_1.compareVersions)(PKG.version, npmVersion) < 1) {
        logger.info('current version older than NPM version, incrementing semver');
        const newVersionParts = npmVersion.split('.').map(Number);
        newVersionParts[2]++;
        pkgVersion = newVersionParts.join('.');
        logger.info(`new version: ${pkgVersion}`);
        // update package.json
        let file = await (0, promises_1.readFile)('./package.json', 'utf8');
        file = file.replace(`"${PKG.version}"`, `"${pkgVersion}"`);
        await (0, promises_1.writeFile)('./package.json', file);
        logger.info('updated package.json');
    }
    const currentCommitHashRslt = await execPromise('git rev-parse HEAD');
    const commitHash = currentCommitHashRslt.stdout.trim();
    let configFile = await (0, promises_1.readFile)('./src/config.ts', 'utf8');
    configFile = configFile.replace(/GIT_COMMIT_HASH = '.+'/mi, `GIT_COMMIT_HASH = '${commitHash}'`);
    await (0, promises_1.writeFile)('./src/config.ts', configFile);
    logger.info(`updated config.ts w latest commit hash: ${commitHash}`);
    logger.info('building package...');
    await execPromise('npm run build');
    logger.info('publishing...');
    // publish to NPM
    //
    // CMD below to login to NPM
    // npm set "//registry.npmjs.org/:_authToken=$NPM_TOKEN"
    //
    await execPromise('npm publish --access public');
    logger.info('published to NPM, adding changes to git');
    // add changes to git
    await execPromise('git add .');
    // commit the changes
    await execPromise(`git commit -m "chore: publish v${pkgVersion}"`);
    // tag the commit
    await execPromise(`git tag v${pkgVersion}`);
    // push the changes
    await execPromise('git push');
    // push the tags
    await execPromise('git push --tags');
    logger.info('pushed changes to git. Done.');
    async function getNpmVersion() {
        const { stdout } = await execPromise(`npm show ${PKG.name} version`);
        return stdout.trim();
    }
}
async function readPackageJson() {
    const pkg = await (0, promises_1.readFile)('./package.json', 'utf8');
    return JSON.parse(pkg);
}
main();
