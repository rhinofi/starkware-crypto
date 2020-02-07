/////////////////////////////////////////////////////////////////////////////////
// Copyright 2019 StarkWare Industries Ltd.                                    //
//                                                                             //
// Licensed under the Apache License, Version 2.0 (the "License").             //
// You may not use this file except in compliance with the License.            //
// You may obtain a copy of the License at                                     //
//                                                                             //
// https://www.starkware.co/open-source-license/                               //
//                                                                             //
// Unless required by applicable law or agreed to in writing,                  //
// software distributed under the License is distributed on an "AS IS" BASIS,  //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    //
// See the License for the specific language governing permissions             //
// and limitations under the License.                                          //
/////////////////////////////////////////////////////////////////////////////////

const BN = require('bn.js');
const hash = require('hash.js');
const elliptic = require('elliptic');
const assert = require('assert');
const cpoints = require('./constant_points.js');

const constant_points_hex = cpoints.constant_points;

const prime = new BN('800000000000011000000000000000000000000000000000000000000000001', 16);
exports.prime = prime;

const stark_ec = new elliptic.ec(
  new elliptic.curves.PresetCurve({
    type: 'short',
    prime: null,
    p: prime,
    a: '00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001',
    b: '06f21413 efbe40de 150e596d 72f7a8c5 609ad26c 15c915c1 f4cdfcb9 9cee9e89',
    n: '08000000 00000010 ffffffff ffffffff b781126d cae7b232 1e66a241 adc64d2f',
    hash: hash.sha256,
    gRed: false,
    g: constant_points_hex[1],
  })
);
exports.ec = stark_ec;

function as_point(coords) {
  return stark_ec.curve.point(new BN(coords[0], 16), new BN(coords[1], 16));
}

const constant_points = constant_points_hex.map(as_point);
exports.constant_points = constant_points;
const shift_point = constant_points[0];
exports.shift_point = shift_point;

function pedersen(input) {
  const zero = new BN('0');
  const one = new BN('1');
  var point = shift_point;
  for (var i = 0; i < input.length; i++) {
    var x = new BN(input[i], 16);
    assert(x.gte(zero) && x.lt(prime), 'Invalid input: ' + input[i]);
    for (var j = 0; j < 252; j++) {
      const pt = constant_points[2 + i * 252 + j];
      assert(!point.getX().eq(pt.getX()));
      if (x.and(one) != 0) {
        point = point.add(pt);
      }
      x = x.shrn(1);
    }
  }
  return point.getX().toString(16);
}
exports.pedersen = pedersen;


function sign_msg(
  instruction_type_bn,
  vault0_bn,
  vault1_bn,
  amount0_bn,
  amount1_bn,
  nonce_bn,
  expiration_timestamp_bn,
  token0,
  token1_or_pub_key) {
  var packed_message = instruction_type_bn
  packed_message = packed_message.ushln(31).add(vault0_bn);
  packed_message = packed_message.ushln(31).add(vault1_bn);
  packed_message = packed_message.ushln(63).add(amount0_bn);
  packed_message = packed_message.ushln(63).add(amount1_bn);
  packed_message = packed_message.ushln(31).add(nonce_bn);
  packed_message = packed_message.ushln(22).add(expiration_timestamp_bn);
  return pedersen([
    pedersen([token0, token1_or_pub_key]), packed_message.toString(16),
  ]);
}
/*
 Serializes the order message in the canonical format expected by the verifier.
 party_a sells amount_sell coins of token_sell from vault_sell.
 party_a buys amount_buy coins of token_buy into vault_buy.

 Expected types:
 ---------------
 vault_sell, vault_buy - uint31 (as int)
 amount_sell, amount_buy - uint63 (as decimal string)
 token_sell, token_buy - uint256 field element strictly less than the prime (as hex string with 0x)
 nonce - uint31 (as int)
 expiration_timestamp - uint22 (as int).
*/
exports.get_limit_order_msg = function (
  vault_sell,
  vault_buy,
  amount_sell,
  amount_buy,
  token_sell,
  token_buy,
  nonce,
  expiration_timestamp
) {
  assert(
    token_sell.substring(0, 2) == '0x' && token_buy.substring(0, 2) == '0x',
    'Hex strings expected to be prefixed with 0x.'
  );
  const vault_sell_bn = new BN(vault_sell);
  const vault_buy_bn = new BN(vault_buy);
  const amount_sell_bn = new BN(amount_sell, 10);
  const amount_buy_bn = new BN(amount_buy, 10);
  const token_sell_bn = new BN(token_sell.substring(2), 16);
  const token_buy_bn = new BN(token_buy.substring(2), 16);
  const nonce_bn = new BN(nonce);
  const expiration_timestamp_bn = new BN(expiration_timestamp);

  const zero = new BN('0');
  const two_pow_22 = new BN('400000', 16);
  const two_pow_31 = new BN('80000000', 16);
  const two_pow_63 = new BN('8000000000000000', 16);
  assert(vault_sell_bn.gte(zero));
  assert(vault_buy_bn.gte(zero));
  assert(amount_sell_bn.gte(zero));
  assert(amount_buy_bn.gte(zero));
  assert(token_sell_bn.gte(zero));
  assert(token_buy_bn.gte(zero));
  assert(nonce_bn.gte(zero));
  assert(expiration_timestamp_bn.gte(zero));
  assert(vault_sell_bn.lt(two_pow_31));
  assert(vault_buy_bn.lt(two_pow_31));
  assert(amount_sell_bn.lt(two_pow_63));
  assert(amount_buy_bn.lt(two_pow_63));
  assert(token_sell_bn.lt(prime));
  assert(token_buy_bn.lt(prime));
  assert(nonce_bn.lt(two_pow_31));
  assert(expiration_timestamp_bn.lt(two_pow_22));

  const instruction_type = zero;
  return sign_msg(instruction_type, vault_sell_bn, vault_buy_bn, amount_sell_bn, amount_buy_bn,
    nonce_bn, expiration_timestamp_bn, token_sell.substring(2), token_buy.substring(2))
};

/*
 Serializes the transfer message in the canonical format expected by the verifier.
 The sender transfer 'amount' coins of 'token' from vault with id sender_vault_id to vault with id
 receiver_vault_id. The receiver's public key is receiver_public_key.
 Expected types:
 ---------------
 amount - uint63 (as decimal string)
 nonce - uint31 (as int)
 sender_vault_id uint31 (as int)
 token - uint256 field element strictly less than the prime (as hex string with 0x)
 receiver_vault_id - uint31 (as int)
 receiver_public_key - uint256 field element strictly less than the prime (as hex string with 0x)
 expiration_timestamp - uint22 (as int).
*/
exports.get_transfer_msg = function (
  amount,
  nonce,
  sender_vault_id,
  token,
  receiver_vault_id,
  receiver_public_key,
  expiration_timestamp,
) {
  assert(
    token.substring(0, 2) == '0x' && receiver_public_key.substring(0, 2) == '0x',
    'Hex strings expected to be prefixed with 0x.'
  );
  const amount_bn = new BN(amount, 10);
  const nonce_bn = new BN(nonce);
  const sender_vault_id_bn = new BN(sender_vault_id);
  const token_bn = new BN(token.substring(2), 16);
  const receiver_vault_id_bn = new BN(receiver_vault_id);
  const receiver_public_key_bn = new BN(receiver_public_key.substring(2), 16)
  const expiration_timestamp_bn = new BN(expiration_timestamp);

  const zero = new BN('0');
  const one = new BN('1');
  const two_pow_22 = new BN('400000', 16);
  const two_pow_31 = new BN('80000000', 16);
  const two_pow_63 = new BN('8000000000000000', 16);
  assert(amount_bn.gte(zero));
  assert(nonce_bn.gte(zero));
  assert(sender_vault_id_bn.gte(zero));
  assert(token_bn.gte(zero));
  assert(receiver_vault_id_bn.gte(zero));
  assert(receiver_public_key_bn.gte(zero));
  assert(expiration_timestamp_bn.gte(zero));
  assert(amount_bn.lt(two_pow_63));
  assert(nonce_bn.lt(two_pow_31));
  assert(sender_vault_id_bn.lt(two_pow_31));
  assert(token_bn.lt(prime));
  assert(receiver_vault_id_bn.lt(two_pow_31));
  assert(receiver_public_key_bn.lt(prime));
  assert(expiration_timestamp_bn.lt(two_pow_22));

  const instruction_type = one;
  return sign_msg(instruction_type, sender_vault_id_bn, receiver_vault_id_bn, amount_bn, zero, nonce_bn,
    expiration_timestamp_bn, token.substring(2), receiver_public_key.substring(2))
};

/*
 The function _truncateToN in lib/elliptic/ec/index.js does a shift-right of 4 bits
 in some cases. This function does the opposite operation so that
   _truncateToN(fix_message(msg)) == msg.
*/
function fix_message(msg) {
  // Convert to BN to remove leading zeros.
  msg = new BN(msg, 16).toString(16);

  if (msg.length <= 62) {
    // In this case, msg should not be transformed, as the byteLength() is at most 31,
    // so delta < 0 (see _truncateToN).
    return msg;
  } else {
    assert(msg.length == 63);
    // In this case delta will be 4 so we perform a shift-left of 4 bits by adding a zero.
    return msg + '0';
  }
}

/*
 Signs a message using the provided key.
 key should be an elliptic.keyPair with a valid private key.
 Returns an elliptic.Signature.
*/
exports.sign = function (key_pair, msg) {
  return key_pair.sign(fix_message(msg));
};

/*
 Verifies a message using the provided key.
 key should be an elliptic.keyPair with a valid public key.
 msg_signature should be an elliptic.Signature.
 Returns a boolean true if the verification succeeds.
*/
exports.verify = function (key_pair, msg, msg_signature) {
  return key_pair.verify(fix_message(msg), msg_signature);
};
