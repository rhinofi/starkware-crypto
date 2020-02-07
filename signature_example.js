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

const starkware_crypto = require('./signature.js');
const assert = require('assert');
const test_data = require('./signature_test_data.json');

//=================================================================================================
// Test Pedersen Hash
//=================================================================================================

for (var hash_test_data of [
  test_data.hash_test.pedersen_hash_data_1, test_data.hash_test.pedersen_hash_data_2]) {
  var result = starkware_crypto.pedersen([
    hash_test_data.input_1.substring(2),
    hash_test_data.input_2.substring(2)]);
  var expectedResult = hash_test_data.output.substring(2);
  assert(result == expectedResult, 'Got: ' + result + ', Expected: ' + expectedResult);
}

//=================================================================================================
// Example: Signing a StarkEx Order:
//=================================================================================================

var private_key = test_data.meta_data.party_a_order.private_key.substring(2);
var key_pair = starkware_crypto.ec.keyFromPrivate(private_key, 'hex');
var public_key = starkware_crypto.ec.keyFromPublic(key_pair.getPublic(true, 'hex'), 'hex');
var public_key_x = public_key.pub.getX();

assert(
  public_key_x.toString(16) === test_data.settlement.party_a_order.public_key.substring(2),
  'Got: ' + public_key_x.toString(16) +
  ' Expected: ' + test_data.settlement.party_a_order.public_key.substring(2)
);

var party_a_order = test_data.settlement.party_a_order
var msg = starkware_crypto.get_limit_order_msg(
  party_a_order.vault_id_sell, // vault_sell (uint31)
  party_a_order.vault_id_buy, // vault_buy (uint31)
  party_a_order.amount_sell, // amount_sell (uint63 decimal str)
  party_a_order.amount_buy, // amount_buy (uint63 decimal str)
  party_a_order.token_sell, // token_sell (hex str with 0x prefix < prime)
  party_a_order.token_buy, // token_buy (hex str with 0x prefix < prime)
  party_a_order.nonce, // nonce (uint31)
  party_a_order.expiration_timestamp // expiration_timestamp (uint22)
);

assert(msg === test_data.meta_data.party_a_order.message_hash.substring(2),
    'Got: ' + msg + ' Expected: ' + test_data.meta_data.party_a_order.message_hash.substring(2)
);

var msg_signature = starkware_crypto.sign(key_pair, msg);
var r = msg_signature.r;
var w = msg_signature.s.invm(starkware_crypto.ec.n);

assert(starkware_crypto.verify(public_key, msg, msg_signature));
assert(r.toString(16) === party_a_order.signature.r.substring(2),
    'Got: ' + r.toString(16) + ' Expected: ' + party_a_order.signature.r.substring(2)
);
assert(w.toString(16) === party_a_order.signature.w.substring(2),
    'Got: ' + w.toString(16) + ' Expected: ' + party_a_order.signature.w.substring(2)
);

// The following is the JSON representation of an order:
console.log('Order JSON representation: ');
console.log(party_a_order);
console.log('\n');


//=================================================================================================
// Example: StarkEx Transfer:
//=================================================================================================

var private_key = test_data.meta_data.transfer_order.private_key.substring(2);
var key_pair = starkware_crypto.ec.keyFromPrivate(private_key, 'hex');
var public_key = starkware_crypto.ec.keyFromPublic(key_pair.getPublic(true, 'hex'), 'hex');
var public_key_x = public_key.pub.getX();

assert( public_key_x.toString(16) === test_data.transfer_order.public_key.substring(2),
    'Got: ' +  public_key_x.toString(16) +
    ' Expected: ' + test_data.transfer_order.public_key.substring(2)
);

var transfer = test_data.transfer_order
var msg = starkware_crypto.get_transfer_msg(
  transfer.amount, // amount (uint63 decimal str)
  transfer.nonce, // nonce (uint31)
  transfer.sender_vault_id, // sender_vault_id (uint31)
  transfer.token, // token (hex str with 0x prefix < prime)
  transfer.target_vault_id, // target_vault_id (uint31)
  transfer.target_public_key, // target_public_key (hex str with 0x prefix < prime)
  transfer.expiration_timestamp // expiration_timestamp (uint22)
);

assert(msg === test_data.meta_data.transfer_order.message_hash.substring(2),
    'Got: ' + msg + ' Expected: ' + test_data.meta_data.transfer_order.message_hash.substring(2)
);

// The following is the JSON representation of a transfer:
console.log('Transfer JSON representation: ');
console.log(transfer);
console.log('\n');

//=================================================================================================
// Example: And adding a matching order to create a settlement:
//=================================================================================================

var private_key = test_data.meta_data.party_b_order.private_key.substring(2);
var key_pair = starkware_crypto.ec.keyFromPrivate(private_key, 'hex');
var public_key = starkware_crypto.ec.keyFromPublic(key_pair.getPublic(true, 'hex'), 'hex');
var public_key_x = public_key.pub.getX();

assert( public_key_x.toString(16) === test_data.settlement.party_b_order.public_key.substring(2),
    'Got: ' +  public_key_x.toString(16) +
    ' Expected: ' + test_data.settlement.party_b_order.public_key.substring(2)
);

var party_b_order = test_data.settlement.party_b_order
var msg = starkware_crypto.get_limit_order_msg(
  party_b_order.vault_id_sell, // vault_sell (uint31)
  party_b_order.vault_id_buy, // vault_buy (uint31)
  party_b_order.amount_sell, // amount_sell (uint63 decimal str)
  party_b_order.amount_buy, // amount_buy (uint63 decimal str)
  party_b_order.token_sell, // token_sell (hex str with 0x prefix < prime)
  party_b_order.token_buy, // token_buy (hex str with 0x prefix < prime)
  party_b_order.nonce, // nonce (uint31)
  party_b_order.expiration_timestamp // expiration_timestamp (uint22)
);

assert(msg === test_data.meta_data.party_b_order.message_hash.substring(2),
    'Got: ' + msg + ' Expected: ' + test_data.meta_data.party_b_order.message_hash.substring(2)
);

var msg_signature = starkware_crypto.sign(key_pair, msg);
var r = msg_signature.r;
var w = msg_signature.s.invm(starkware_crypto.ec.n);

assert(starkware_crypto.verify(public_key, msg, msg_signature));
assert(r.toString(16) === party_b_order.signature.r.substring(2),
    'Got: ' + r.toString(16) + ' Expected: ' + party_b_order.signature.r.substring(2)
);
assert(w.toString(16) === party_b_order.signature.w.substring(2),
    'Got: ' + w.toString(16) + ' Expected: ' + party_b_order.signature.w.substring(2)
);

// The following is the JSON representation of a settlement:
console.log('Settlement JSON representation: ');
console.log(test_data.settlement);
