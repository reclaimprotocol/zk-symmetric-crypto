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
}