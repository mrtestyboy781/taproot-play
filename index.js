const assert = require('assert');
const bitcoin = require('bitcoinjs-lib');
const bitcoinMessage = require('bitcoinjs-message');
const secp256k1 = require('secp256k1');
const BN = require('bn.js');
const { createHash } = require('crypto');
const elliptic_1 = require('elliptic');

const secp256 = new elliptic_1.ec('secp256k1');

const {
    mainnet,
    testnet,
    path,
    message,
    opcodes,
} = require('./constants');

const generateTestnet = parseInt(process.env.TESTNET) === 1;
const {
    xpriv1,
    xpriv2,
    xpub1,
    xpub2,
    xpub3,
    network,
} = generateTestnet ? testnet : mainnet;

// Bip32 Nodes
const hdNode1 = bitcoin.bip32.fromBase58(xpriv1, network);
const hdNode2 = bitcoin.bip32.fromBase58(xpriv2, network);

// Generate keypairs from bip32 paths
const keyPair1 = hdNode1.derivePath(path);
const keyPair2 = hdNode2.derivePath(path);

//
// Generate multi sig addresses from extended public keys
//
const multisigPubkeys = [xpub1, xpub2, xpub3].map(
    (xpub) => bitcoin.bip32.fromBase58(xpub, network).derivePath(path).publicKey,
);


// Taproot pubkeys don't have coordinate indicator
const multisigPubkeysNoX = multisigPubkeys.map((p) => p.slice(1));

console.log("2-of-3 Mutisig Keys")
multisigPubkeysNoX.map(p => console.log(`${p.toString('hex')}`));

// Taproot 2-of-3 multi-sig is...
//
// Key Path: 2-of-2 with both hot keys
// Script Path: 2-of-2 with either hot key and cold key
//

const leaf1 = bitcoin.payments.p2tr_ns({
    pubkeys: [multisigPubkeysNoX[0], multisigPubkeysNoX[2]],
    network,
}).output;

const leaf2 = bitcoin.payments.p2tr_ns({
    pubkeys: [multisigPubkeysNoX[1], multisigPubkeysNoX[2]],
    network,
}).output;

const p2tr_musig = bitcoin.payments.p2tr({
    pubkeys: multisigPubkeysNoX.slice(0, 2),
    redeems: [
        {
            output: leaf1,
            weight: 1,
        },
        {
            output: leaf2,
            weight: 1,
        },
    ],
    network,
});

console.log(`\nP2TR address : ${p2tr_musig.address}`);

//
// Could spend from keypath in 2 ways
//
// Sloppy : Both private keys are known on same
// machine, and tweaked private key is produced
// to make a valid signature
//
// More Safe : Two signatures are created on separate
// machines and aggregated to form valid
// signature. This requires cooperative nonce
// generation to form an aggregated signing
// nonce used in the Hash(R_agg || tweakedPubkey || msgHash)
// so both schnorr signatures have the same hash digest to
// multiply against


// the message hash to sign
const msgHash = bitcoinMessage.magicHash(message);

//
// Sloppy way
//

// Making multi-sig taproot signature requires calculating tweaked private key
const innerPubkey = bitcoin.taproot.aggregateMuSigPubkeys([multisigPubkeysNoX[0], multisigPubkeysNoX[1]]);
const taptree = bitcoin.taproot.getHuffmanTaptree([leaf1, leaf2], [1, 1]);
const expectedMuSigPubkey = bitcoin.taproot.tapTweakPubkey(innerPubkey, taptree.root);

// FIXME - bitgo
//
// hardcoded challenge factor for keypair1 for now, since its not passed up from bitgo library
//
// ideally bitgo library would pass these up to caller from aggregateMuSigPubkeys
// so you can back-apply the challenge factors to the pubkeys
//
const challenge = Buffer.from('da7e79b8d9b1ac1d38a7633e24bcad65ec9b5d9e50815b33c120d048a10dd5a3', 'hex');

// private key is tweaked with challenge factor that was applied to the pubkey1
const pk1_mod = secp256k1.privateKeyTweakMul(
    bitcoin.schnorrBip340.forceEvenYPrivKey(keyPair1.privateKey),
    challenge,
);

// inner private key calculated
const innerpk = secp256k1.privateKeyTweakAdd(
    bitcoin.schnorrBip340.forceEvenYPrivKey(pk1_mod),
    bitcoin.schnorrBip340.forceEvenYPrivKey(keyPair2.privateKey),
);

// tweak inner private key to make tweaked private key
const tweakedMuSigPrivateKey = bitcoin.taproot.tapTweakPrivkey(
    innerPubkey,
    innerpk,
    taptree.root,
);
const tweakedPubkeyMuSig = secp256k1.publicKeyCreate(tweakedMuSigPrivateKey).slice(1);
const sig_p2tr_musig = bitcoin.schnorrBip340.signSchnorr(msgHash, tweakedMuSigPrivateKey);
// verify the expected MuSigPubkey matches what is calculated from tweaked private key
assert(expectedMuSigPubkey.pubkey.toString('hex') === tweakedPubkeyMuSig.toString('hex'));
// verify valid signature
assert(bitcoin.schnorrBip340.verifySchnorr(msgHash, expectedMuSigPubkey.pubkey, sig_p2tr_musig));

console.log(`\nValid signature from tweaked private key : ${sig_p2tr_musig.toString('hex')}`);

//
// More secure way
//
// make collaborative nonces and
// have added signatures
//


//
// COPIED BITGO CODE that isn't exported
//
const TWO = new BN(2);
const n = secp256.curve.n;
const G = secp256.curve.g;

function fromBuffer(d) {
    return new BN(d);
}

function toBuffer(d) {
    return d.toArrayLike(Buffer, 'be', 32);
}

function sha256(message) {
    return createHash('sha256')
        .update(message)
        .digest();
}

function taggedHash(tagString, msg) {
    if (typeof tagString !== 'string') {
        throw new TypeError('invalid argument');
    }
    if (!Buffer.isBuffer(msg)) {
        throw new TypeError('invalid argument');
    }
    const tagHash = sha256(Buffer.from(tagString, 'utf8'));
    return sha256(Buffer.concat([tagHash, tagHash, msg]));
}

function decodeXOnlyPoint(bytes) {
    if (!Buffer.isBuffer(bytes) || bytes.length !== 32) {
        throw new Error('invalid pubkey');
    }
    if (bytes.compare(EC_P) >= 0) {
        throw new Error('invalid pubkey');
    }
    return secp256k1.curve.pointFromX(fromBuffer(bytes), /* odd */ false);
}

function encodeXOnlyPoint(P) {
    return toBuffer(P.getX());
}

function hasEvenY(P) {
    return (
        !P.isInfinity()
    && P.getY()
        .umod(TWO)
        .isZero()
    );
}

function forceEvenYKeyPair(d) {
    const dd = fromBuffer(d);
    const P = G.mul(dd);
    if (hasEvenY(P)) {
        return { dd, P: encodeXOnlyPoint(P) };
    }
    return { dd: n.sub(dd), P: encodeXOnlyPoint(P) };
}

//
// MODIFIED BITGO CODE
//

// Create nonces that have even Y coordinates
function createSchnorrNonce() {
    const k0 = new BN(bitcoin.ECPair.makeRandom().__D.toString('hex'), 16);
    const R = G.mul(k0);
    if (R.isInfinity()) {
        throw new Error('R at Infinity');
    }
    const k = hasEvenY(R) ? k0 : n.sub(k0);
    return { k, R: G.mul(k) };
}

// aggregate nonce points and if not even, negate the point
// and signal the negation happened back to caller
// so negations can be applied back to nonces
function aggregateSchnorrNonces(nonces) {
    const aggregateNonce = nonces.reduce((prev, curr) =>
        prev.add(curr)
    );

    if (!hasEvenY(aggregateNonce)) {
        return { negated: true, R_agg: aggregateNonce.neg() };
    }
    return { negated: false, R_agg: aggregateNonce };
}

// the schnorr digest in
//
// s = nonce + Hash(aggregatedNonce || tweakedPubkey || msgHash) * d
//
function musigDigest(R_agg, P, hash) {
    return fromBuffer(
      taggedHash(
        'BIP0340/challenge',
        Buffer.concat([encodeXOnlyPoint(R_agg), P, hash]),
      ),
    ).mod(n);
}

// FIXME bitgo
//
// the only difference here is that
// we allow the caller to specify the
// nonce and aggregated nonce point so
// the same hash digest can be used
// for multiple signatures keeping
// linearity
//
// hash : message hash
// d : private key with challenge factor from aggregated musig pubkey applied
// k : signing nonce
// R_agg : aggregated nonce
// P : aggregated and tweaked MuSig pubkey
//
function signSchnorr(hash, d, k, R_agg, P) {
  const { dd } = forceEvenYKeyPair(d);
  const e = musigDigest(R_agg, P, hash);
  return k.add(e.mul(dd)).mod(n);
}

//
// End modified BitGo Code
//


//
// For making signatures to aggregate need to generate
// an aggregated nonce
//
let { k: k1, R: R1 } = createSchnorrNonce();
let { k: k2, R: R2 } = createSchnorrNonce();
const { negated, R_agg } = aggregateSchnorrNonces([R1, R2]);
// If we had to negate the aggregated nonce have to back
// apply it to the singular nonces
//
// https://github.com/bitcoinops/taproot-workshop/blob/master/solutions/2.2-taptweak-solutions.ipynb
//
if (negated) {
    k1 = n.sub(k1)
    k2 = n.sub(k2)
}


//
// still need to apply back the tap tweak to one
// of the private keys used for signing
//
const tweakedPrivateKey1 = bitcoin.taproot.tapTweakPrivkey(
    innerPubkey,
    pk1_mod,
    taptree.root,
);
const sig_tr_1 = signSchnorr(msgHash, tweakedPrivateKey1, k1, R_agg, tweakedPubkeyMuSig);
const sig_tr_2 = signSchnorr(msgHash, keyPair2.privateKey, k2, R_agg, tweakedPubkeyMuSig);
const S_agg = fromBuffer(sig_tr_1).add(fromBuffer(sig_tr_2)).mod(n);
const sig = Buffer.concat([
  encodeXOnlyPoint(R_agg),
  toBuffer(S_agg),
]);
assert(bitcoin.schnorrBip340.verifySchnorr(msgHash, tweakedPubkeyMuSig, sig));

//
// another option is to just add the tweak to the signatures after the fact.
//
// this is a more likely option since neither of the signatories will
// have to know to apply a tweak; something the signature aggregator can do
//
const digest = musigDigest(R_agg, tweakedPubkeyMuSig, msgHash);
const tweak = taggedHash('TapTweak', Buffer.concat([innerPubkey, taptree.root]));
const tweakFactor = digest.mul(fromBuffer(tweak));
const sig_tr_1_alt = signSchnorr(msgHash, pk1_mod, k1, R_agg, tweakedPubkeyMuSig);
const sig_tr_2_alt = signSchnorr(msgHash, keyPair2.privateKey, k2, R_agg, tweakedPubkeyMuSig);
const S_agg_2 = fromBuffer(sig_tr_1_alt).add(fromBuffer(sig_tr_2_alt)).add(tweakFactor).mod(n);
const sig2 = Buffer.concat([
  encodeXOnlyPoint(R_agg),
  toBuffer(S_agg_2),
]);
assert(bitcoin.schnorrBip340.verifySchnorr(msgHash, tweakedPubkeyMuSig, sig2));

// Aggregated signature is
//
// (R,s) = [R_agg || (s1+s2+digest*tweak)]
//
console.log(`\nAggregated signature Debug`);
console.log(`R_agg : ${encodeXOnlyPoint(R_agg).toString('hex')}`);
console.log(`s1 : ${sig_tr_1_alt.toString('hex')}`);
console.log(`s2 : ${sig_tr_2_alt.toString('hex')}`);
console.log(`tweaked digest : ${tweakFactor.mod(n).toString('hex')}`);
console.log(`\nValid aggregated signature : ${sig2.toString('hex')}`);

