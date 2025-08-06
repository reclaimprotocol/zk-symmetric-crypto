"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeRemoteFileFetch = makeRemoteFileFetch;
exports.makeLocalFileFetch = makeLocalFileFetch;
const config_1 = require("./config");
const DEFAULT_REMOTE_BASE_URL = `https://github.com/reclaimprotocol/zk-symmetric-crypto/raw/${config_1.GIT_COMMIT_HASH}/resources/`;
const DEFAULT_BASE_PATH = '../resources';
/**
 * Fetches ZK resources from a remote server.
 * Assumes the structure of the resources is:
 * BASE_URL/{engine}/{filename}
 *
 * By default, it uses the resources from a specific commit
 * of the `zk-symmetric-crypto` repository.
 */
function makeRemoteFileFetch({ baseUrl = DEFAULT_REMOTE_BASE_URL, } = {}) {
    return {
        async fetch(engine, filename) {
            const url = `${baseUrl}/${engine}/${filename}`;
            const res = await fetch(url);
            if (!res.ok) {
                throw new Error(`${engine}-${filename} fetch failed with code: ${res.status}`);
            }
            const arr = await res.arrayBuffer();
            return new Uint8Array(arr);
        },
    };
}
/**
 * Fetches ZK resources from the local file system.
 * Assumes the structure of the resources is:
 * BASE_PATH/{engine}/{filename}
 */
function makeLocalFileFetch({ basePath = DEFAULT_BASE_PATH } = {}) {
    return {
        async fetch(engine, filename) {
            const path = `${basePath}/${engine}/${filename}`;
            // import here to avoid loading fs in
            // a browser env
            const { readFile } = await Promise.resolve().then(() => __importStar(require('fs/promises')));
            const { join } = await Promise.resolve().then(() => __importStar(require('path')));
            const fullPath = join(__dirname, path);
            const buff = await readFile(fullPath);
            return buff;
        },
    };
}
