module.exports = {
	'roots': [
		'<rootDir>/src'
	],
	modulePathIgnorePatterns: [
		'<rootDir>/node_modules'
	],
	'testMatch': [
		'**/tests/*.test.+(ts|tsx|js)',
	],
	transform: {
		'^.+\\.(js|ts|tsx)?$': [
			'@swc/jest',
		]
	},
	testTimeout: 300000, // 5 minutes for ZK proof generation
}