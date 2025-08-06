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
exports.initGnarkAlgorithm = initGnarkAlgorithm;
exports.strToUint8Array = strToUint8Array;
exports.serialiseGnarkWitness = serialiseGnarkWitness;
exports.generateGnarkWitness = generateGnarkWitness;
exports.executeGnarkFn = executeGnarkFn;
exports.executeGnarkFnAndGetJson = executeGnarkFnAndGetJson;
const js_base64_1 = require("js-base64");
const BIN_PATH = '../../bin/gnark';
let globalGnarkLib;
// golang uses different arch names
// for some archs -- so this map corrects the name
const ARCH_MAP = {
    'x64': 'x86_64',
};
const INIT_ALGS = {};
async function loadGnarkLib() {
    const koffiMod = await Promise.resolve().then(() => __importStar(require('koffi'))).catch(() => undefined);
    if (!koffiMod) {
        throw new Error('Koffi not available, cannot use gnark');
    }
    const { join } = await Promise.resolve().then(() => __importStar(require('path')));
    const { default: koffi } = koffiMod;
    koffi.reset(); //otherwise tests will fail
    // define object GoSlice to map to:
    // C type struct { void *data; GoInt len; GoInt cap; }
    const GoSlice = koffi.struct('GoSlice', {
        data: 'void *',
        len: 'longlong',
        cap: 'longlong'
    });
    const ProveReturn = koffi.struct('ProveReturn', {
        r0: 'void *',
        r1: 'longlong',
    });
    const LibReturn = koffi.struct('LibReturn', {
        r0: 'void *',
        r1: 'longlong',
    });
    const arch = ARCH_MAP[process.arch] || process.arch;
    const platform = process.platform;
    const libVerifyPath = join(__dirname, `${BIN_PATH}/${platform}-${arch}-libverify.so`);
    const libProvePath = join(__dirname, `${BIN_PATH}/${platform}-${arch}-libprove.so`);
    try {
        const libVerify = koffi.load(libVerifyPath);
        const libProve = koffi.load(libProvePath);
        return {
            verify: libVerify.func('Verify', 'unsigned char', [GoSlice]),
            free: libProve.func('Free', 'void', ['void *']),
            vfree: libVerify.func('VFree', 'void', ['void *']), //free in verify library
            prove: libProve.func('Prove', ProveReturn, [GoSlice]),
            initAlgorithm: libProve.func('InitAlgorithm', 'unsigned char', ['unsigned char', GoSlice, GoSlice]),
            generateThresholdKeys: libVerify.func('GenerateThresholdKeys', LibReturn, [GoSlice]),
            oprfEvaluate: libVerify.func('OPRFEvaluate', LibReturn, [GoSlice]),
            generateOPRFRequest: libProve.func('GenerateOPRFRequestData', LibReturn, [GoSlice]),
            toprfFinalize: libProve.func('TOPRFFinalize', LibReturn, [GoSlice]),
            koffi
        };
    }
    catch (err) {
        if (err.message.includes('not a mach-o')) {
            throw new Error(`Gnark library not compatible with OS/arch (${platform}/${arch})`);
        }
        else if (err.message.toLowerCase().includes('no such file')) {
            throw new Error(`Gnark library not built for OS/arch (${platform}/${arch})`);
        }
        throw err;
    }
}
async function initGnarkAlgorithm(id, fileExt, fetcher, logger) {
    globalGnarkLib ??= loadGnarkLib();
    const lib = await globalGnarkLib;
    if (INIT_ALGS[id]) {
        return lib;
    }
    const [pk, r1cs] = await Promise.all([
        fetcher.fetch('gnark', `pk.${fileExt}`, logger),
        fetcher.fetch('gnark', `r1cs.${fileExt}`, logger),
    ]);
    const f1 = { data: pk, len: pk.length, cap: pk.length };
    const f2 = { data: r1cs, len: r1cs.length, cap: r1cs.length };
    await lib.initAlgorithm(id, f1, f2);
    INIT_ALGS[id] = true;
    return lib;
}
function strToUint8Array(str) {
    return new TextEncoder().encode(str);
}
function serialiseGnarkWitness(cipher, input) {
    const json = generateGnarkWitness(cipher, input);
    return strToUint8Array(JSON.stringify(json));
}
function generateGnarkWitness(cipher, input) {
    //input is bits, we convert them back to bytes
    return {
        cipher: cipher + ('toprf' in input ? '-toprf' : ''),
        key: 'key' in input
            ? js_base64_1.Base64.fromUint8Array(input.key)
            : undefined,
        nonce: js_base64_1.Base64.fromUint8Array(input.nonce),
        counter: input.counter,
        input: js_base64_1.Base64.fromUint8Array(input.in),
        toprf: generateTOPRFParams()
    };
    function generateTOPRFParams() {
        if (!('toprf' in input)) {
            return {};
        }
        const { pos, len, domainSeparator, output, responses } = input.toprf;
        return {
            pos: pos,
            len: len,
            domainSeparator: js_base64_1.Base64
                .fromUint8Array(strToUint8Array(domainSeparator)),
            output: js_base64_1.Base64.fromUint8Array(output),
            responses: responses.map(mapResponse),
            mask: 'mask' in input
                ? js_base64_1.Base64.fromUint8Array(input.mask)
                : ''
        };
    }
}
function mapResponse({ publicKeyShare, evaluated, c, r }) {
    return {
        publicKeyShare: js_base64_1.Base64.fromUint8Array(publicKeyShare),
        evaluated: js_base64_1.Base64.fromUint8Array(evaluated),
        c: js_base64_1.Base64.fromUint8Array(c),
        r: js_base64_1.Base64.fromUint8Array(r),
    };
}
function executeGnarkFn(fn, jsonInput) {
    const wtns = {
        data: typeof jsonInput === 'string'
            ? Buffer.from(jsonInput)
            : jsonInput,
        len: jsonInput.length,
        cap: jsonInput.length
    };
    return fn(wtns);
}
async function executeGnarkFnAndGetJson(fn, jsonInput) {
    const { free, koffi } = await globalGnarkLib;
    const res = executeGnarkFn(fn, jsonInput);
    const proof = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString();
    free(res.r0); // Avoid memory leak!
    return JSON.parse(proof);
}
