

function serialiseWitness({
	public: publicInputs,
	private: privateInputs,
}) {
	return serialiseData(publicInputs)
}

/**
 * Serialises all values in the data object, in order,
 * into a single Uint8Array. Will use 32 bytes for each
 * value, and will pad with zeroes if the value is not
 * exactly 32 bytes.
 *
 * @param {{ [_: string]: Uint8Array | (number | bigint)[] }} data
 */
function serialiseData(data) {
	const values = Object.values(data)
		.flatMap((key) => Array.isArray(key) ? key : Array.from(key))
	const serialised = new Uint8Array(values.length * 32)
	const dataview = new DataView(serialised.buffer)

	for (const [i, value] of values.entries()) {
		dataview.setBigUint64(i * 32, BigInt(value), true)
	}

	return serialised
}

module.exports = { serialiseWitness }