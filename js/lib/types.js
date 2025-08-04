"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isBarretenbergOperator = void 0;
// **
// type guard for BarretenbergOperator
// **
const isBarretenbergOperator = (operator) => {
    return 'ultrahonkProve' in operator && 'ultrahonkVerify' in operator;
};
exports.isBarretenbergOperator = isBarretenbergOperator;
