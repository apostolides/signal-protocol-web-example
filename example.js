(async ()=>{

    // Bob's Init.

    var KeyHelperBob = libsignal.KeyHelper;
    var storeBob = new SignalProtocolStore();

    var keyIdBob = KeyHelperBob.generateRegistrationId();
    storeBob.put('registrationId',keyIdBob);

    var identityKeyPairBob = await KeyHelperBob.generateIdentityKeyPair();
    storeBob.put('identityKey',identityKeyPairBob);

    var preKeyBob = await KeyHelperBob.generatePreKey(keyIdBob);
    storeBob.storePreKey(preKeyBob.keyId, preKeyBob.keyPair);

    var signedPreKeyBob = await KeyHelperBob.generateSignedPreKey(identityKeyPairBob, keyIdBob);
    storeBob.storeSignedPreKey(signedPreKeyBob.keyId, signedPreKeyBob.keyPair);

    // ---------------------------------------------------------------------------------------------

    // Alice's Init.

    var keyHelperAlice = libsignal.KeyHelper;
    var storeAlice = new SignalProtocolStore();

    var keyIdAlice = keyHelperAlice.generateRegistrationId();
    storeAlice.put('registrationId',keyIdAlice);

    var identityKeyPairAlice = await keyHelperAlice.generateIdentityKeyPair();
    storeAlice.put('identityKey',identityKeyPairAlice);

    var preKeyAlice = await keyHelperAlice.generatePreKey(keyIdAlice);
    storeAlice.storePreKey(preKeyAlice.keyId, preKeyAlice.keyPair);

    var signedPreKeyAlice = await keyHelperAlice.generateSignedPreKey(identityKeyPairAlice, keyIdAlice);
    storeAlice.storeSignedPreKey(signedPreKeyAlice.keyId, signedPreKeyAlice.keyPair);

    // ---------------------------------------------------------------------------------------------

    // Bob will send a message to Alice.

    var addressAlice = new libsignal.SignalProtocolAddress("addressAlice",1);

    var sessionBuilderBob = new libsignal.SessionBuilder(storeBob, addressAlice);

    // Process Alice's keys.
    var promiseBob = sessionBuilderBob.processPreKey({
        registrationId: keyIdAlice,
        identityKey: identityKeyPairAlice.pubKey,
        signedPreKey: {
            keyId: keyIdAlice,
            publicKey: signedPreKeyAlice.keyPair.pubKey,
            signature: signedPreKeyAlice.signature
        },
        preKey:{
            keyId: preKeyAlice.keyId,
            publicKey: preKeyAlice.keyPair.pubKey
        }
    });

    promiseBob.then(function onsuccess() {
        // encrypt messages
    });
  
    promiseBob.catch(function onerror(error) {
        // handle identity key conflict
        console.error(error)
    });

    var plaintext = "Hello!";
    console.log(`[*] Original plaintext: ${plaintext}`)

    var sessionCipherBob = new libsignal.SessionCipher(storeBob, addressAlice);
    var ciphertext = await sessionCipherBob.encrypt(plaintext);
    console.log(`[*] Ciphertext: ${ciphertext.body}`);

    // ---------------------------------------------------------------------------------------------

    // Alice will decrypt Bob's message.
    
    var addressBob = new libsignal.SignalProtocolAddress("addressBob",2); 
    var sessionBuilderAlice = new libsignal.SessionBuilder(storeAlice, addressBob);

    // Alice processes Bob's keys.
    var promiseAlice = sessionBuilderAlice.processPreKey({
        registrationId: keyIdBob,
        identityKey: identityKeyPairBob.pubKey,
        signedPreKey: {
            keyId: keyIdBob,
            publicKey: signedPreKeyBob.keyPair.pubKey,
            signature: signedPreKeyBob.signature
        },
        preKey:{
            keyId: preKeyBob.keyId,
            publicKey: preKeyBob.keyPair.pubKey
        }
    });

    promiseAlice.then(function onsuccess() {
        // encrypt messages
    });
  
    promiseAlice.catch(function onerror(error) {
        // handle identity key conflict
        console.error(error)
    });

    var sessionCipherAlice = new libsignal.SessionCipher(storeAlice, addressBob);
    sessionCipherAlice.decryptPreKeyWhisperMessage(ciphertext.body,'binary').then(function(plaintext) {
        // handle plaintext ArrayBuffer
        console.log(`[*] Decrypted Plaintext: ${util.toString(plaintext)}`);
    }).catch(function(error) {
        // handle identity key conflict
    });
  
})();
