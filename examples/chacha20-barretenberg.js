/**
 * ChaCha20 with Barretenberg Example
 * 
 * This example demonstrates how to use ChaCha20 encryption with Barretenberg (Noir) circuits
 * for zero-knowledge proof generation and verification.
 */

const { randomBytes } = require('crypto')
const {
  generateProof,
  verifyProof,
  makeBarretenbergZKOperator,
  CONFIG
} = require('../js/lib/index')
const { makeLocalFileFetch } = require('../js/lib/file-fetch')

async function main() {
  console.log('🔐 ChaCha20 with Barretenberg Example')
  console.log('=====================================\n')

  // Algorithm configuration
  const algorithm = 'chacha20'
  const config = CONFIG[algorithm]
  
  console.log(`Algorithm: ${algorithm}`)
  console.log(`Key size: ${config.keySizeBytes} bytes`)
  console.log(`IV size: ${config.ivSizeBytes} bytes`)
  console.log(`Chunk size: ${config.chunkSize} bytes\n`)

  // Create operator
  const fetcher = makeLocalFileFetch()
  const operator = makeBarretenbergZKOperator({
    algorithm,
    fetcher,
    options: { threads: 1 }
  })

  try {
    // Generate test data
    const plaintext = Buffer.from('Hello, ChaCha20 with Noir circuits! This is a test message for zero-knowledge proofs.')
    const key = randomBytes(config.keySizeBytes)
    const iv = randomBytes(config.ivSizeBytes)
    
    console.log('📝 Test Data:')
    console.log(`Plaintext: "${plaintext.toString()}" (${plaintext.length} bytes)`)
    console.log(`Key: ${key.toString('hex')}`)
    console.log(`IV: ${iv.toString('hex')}\n`)

    // Encrypt data using ChaCha20
    const ciphertext = config.encrypt({
      key,
      iv,
      in: plaintext
    })
    
    console.log('🔒 Encryption:')
    console.log(`Ciphertext: ${ciphertext.toString('hex')} (${ciphertext.length} bytes)\n`)

    // Prepare inputs for proof generation
    const privateInput = { key }
    const publicInput = { ciphertext, iv }

    console.log('⚡ Generating zero-knowledge proof...')
    const startTime = Date.now()
    
    const proof = await generateProof({
      algorithm,
      privateInput,
      publicInput,
      operator
    })
    
    const proofTime = Date.now() - startTime
    console.log(`✅ Proof generated in ${proofTime}ms`)
    console.log(`Proof size: ${proof.proofData.length} bytes\n`)

    // Verify the proof
    console.log('🔍 Verifying proof...')
    const verifyStartTime = Date.now()
    
    await verifyProof({
      proof,
      publicInput,
      operator
    })
    
    const verifyTime = Date.now() - verifyStartTime
    console.log(`✅ Proof verified successfully in ${verifyTime}ms\n`)

    // Test with invalid proof (should fail)
    console.log('🚫 Testing invalid proof...')
    try {
      const invalidProof = { ...proof }
      invalidProof.proofData[0] = (invalidProof.proofData[0] + 1) % 256
      
      await verifyProof({
        proof: invalidProof,
        publicInput,
        operator
      })
      
      console.log('❌ ERROR: Invalid proof was accepted!')
    } catch (error) {
      console.log('✅ Invalid proof correctly rejected\n')
    }

    console.log('🎉 ChaCha20 Barretenberg integration test completed successfully!')
    
  } catch (error) {
    console.error('❌ Error:', error.message)
    process.exit(1)
  } finally {
    // Clean up
    await operator.release?.()
  }
}

if (require.main === module) {
  main().catch(console.error)
}

module.exports = { main }