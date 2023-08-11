import { hrtime } from 'node:process'
import sodium from 'chloride'
import box from 'private-box'

tests()

function tests() { 
  const keys = []
  for (let i = 0; i < 256; i++) {
    keys.push(generateKey())
  }

  console.log('| max recipients count | recipient count | receiver type | msg size (bytes) | decryption time (nanoseconds) |')
  console.log('|---|---|---|---|---|')

  const msgSize = 1028 * 16
  const msgBody = new Buffer.alloc(msgSize)
  sodium.randombytes(msgBody)

  for (const max of [8, 16, 32, 64, 128, 255]) {
    for (const recipientsCount of [2, 8, 16, 32, 64, 128, 255]) {
      if (recipientsCount > max) continue

      const recipients = keys.slice(0, recipientsCount).map(convertToPublicKey)

      for (const receiverType of ['last', 'none']) {
        const receiverIndex = receiverType === 'last' ? recipientsCount - 1 : 255
        const receiver = convertToSecretKey(keys[receiverIndex])

        const shouldDecrypt = receiverType !== 'none'

        const decryptionTime = test({
          max,
          recipients,
          receiver,
          msgBody,
          shouldDecrypt,
        })

        console.log(`| ${max} | ${recipientsCount} | ${receiverType} | ${msgSize} | ${decryptionTime} |`)
      }
    }
  }
}

function test(params) {
  const {
    msgBody,
    max,
    recipients,
    receiver,
    shouldDecrypt,
  } = params

  const privateMsg = box.encrypt(msgBody, recipients, max)

  const start = hrtime.bigint()

  const decryptedMsg = box.decrypt(privateMsg, receiver, max)

  const end = hrtime.bigint()

  if (shouldDecrypt && decryptedMsg == undefined) {
    throw new Error("expected successful decryption")
  }

  const decryptionTime = end - start

  return decryptionTime
}

function generateKey() {
  return sodium.crypto_sign_keypair()
}

function convertToPublicKey(key) {
  const { publicKey } = key
  return sodium.crypto_sign_ed25519_pk_to_curve25519(publicKey)
}

function convertToSecretKey(key) {
  const { secretKey } = key
  return sodium.crypto_sign_ed25519_sk_to_curve25519(secretKey)
}
