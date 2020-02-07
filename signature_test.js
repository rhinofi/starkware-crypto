const starkware_crypto = require('./signature.js');
const assert = require('assert');

function test_signature(msg, expected_r, expected_w) {
    var private_key = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
    var key_pair = starkware_crypto.ec.keyFromPrivate(private_key, 'hex');
    var public_key = starkware_crypto.ec.keyFromPublic(key_pair.getPublic(true, 'hex'), 'hex');

    var msg_signature = starkware_crypto.sign(key_pair, msg);
    assert(starkware_crypto.verify(public_key, msg, msg_signature));

    var r = msg_signature.r;
    var w = msg_signature.s.invm(starkware_crypto.ec.n);
    assert(r.toString(16) === expected_r);
    assert(w.toString(16) === expected_w);
}

// msg of length 61.
test_signature(
    'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47',
    '5f496f6f210b5810b2711c74c15c05244dad43d18ecbbdbe6ed55584bc3b0a2',
    '777aa1a010e06e0eae0162c8121778d863f393a64f33fbc806c33140144af8b'
);

// msg of length 61, with leading zeros.
test_signature(
    '00c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47',
    '5f496f6f210b5810b2711c74c15c05244dad43d18ecbbdbe6ed55584bc3b0a2',
    '777aa1a010e06e0eae0162c8121778d863f393a64f33fbc806c33140144af8b'
);

// msg of length 62.
test_signature(
    'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47a',
    '233b88c4578f0807b4a7480c8076eca5cfefa29980dd8e2af3c46a253490e9c',
    '522ced67a42c09b6bfd74cfc16c11c49d63d79c7e81ae84ee89ff870218c919'
);

// msg of length 63.
test_signature(
    '7465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47a1',
    'b6bee8010f96a723f6de06b5fa06e820418712439c93850dd4e9bde43ddf',
    '1a42d3f507da55c0347818fced04f33e4b78ee6c5b81c777215471b7104ef01'
);
