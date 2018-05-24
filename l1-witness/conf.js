/*jslint node: true */
"use strict";

exports.port = null;
//exports.myUrl = 'wss://mydomain.com/bb';
exports.bServeAsHub = false;
exports.bLight = false;

exports.storage = 'sqlite';


exports.hub = '10.1.26.104:16611';
exports.deviceName = 'Witness';
exports.permanent_pairing_secret = 'randomstring';
exports.control_addresses = ['PEKN50945559A'];
exports.payout_address = 'CRBLL23UPOMSWXYEYW2KFP3G54YW7N4G';

exports.bSingleAddress = true;
exports.THRESHOLD_DISTANCE = 50;
exports.MIN_AVAILABLE_WITNESSINGS = 100;

exports.KEYS_FILENAME = 'keys.json';

exports.admin_email = 'admin@example.org';
exports.from_email = 'bugs@example.org';

console.log('finished witness conf');
