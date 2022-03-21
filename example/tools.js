const crypto = require('crypto');
const BigInteger = require('bigi');
const ecurve = require('ecurve-bn256');
//const ecurve = require('ecurve');
const ecparams = ecurve.getCurveByName('bn256g1');
//const ecparams = ecurve.getCurveByName('secp256k1');
const Point = ecurve.Point;
const Web3EthAbi 	    = require('web3-eth-abi');
const LenPtHexString = 130;
const ByteLenOfSk = 32;
const ErrPointNotOnCurve = "Point is not on curve";
const ErrInvalidHexString = "not a hex string";
const ErrInvalidHexStringLen = "Invalid hex string length";

// buffer
const r 			    = new Buffer("e7e59bebdcee876e84d03832544f5a517e96a9e3f60cd8f564bece6719d5af52", 'hex');

// buffer
let R = baseScarMulti(r);

// sk*G
// return: buff
function baseScarMulti(sk) {
    let curvePt = ecparams.G.multiply(BigInteger.fromBuffer(sk));
    return curvePt.getEncoded(false);
}

// sk*G
// return: buff
function baseScarMultiPt(sk) {
    let curvePt = ecparams.G.multiply(BigInteger.fromBuffer(sk));
    return curvePt
}

// hash
// return:buffer
function h(buff) {
    let sha = crypto.createHash('sha256').update(buff).digest();
    return sha;
}

// hash
// return:hexStr
function hashStr(bufStr) {
		let buff = Buffer.from(bufStr, 'utf8');		
		//console.log("before hash",bufferToHexString(buff));
    let sha = crypto.createHash('sha256').update(buff).digest();
    //console.log("after hash",bufferToHexString(sha));
    return bufferToHexString(sha);
}


// get s
// s = r+sk*m
// return: buffer
function getSBuff(sk, m) {
    let rBig = BigInteger.fromBuffer(r);
    let skBig = BigInteger.fromBuffer(sk);
    let mBig = BigInteger.fromBuffer(m);
    let retBig;
    retBig = rBig.add(skBig.multiply(mBig).mod(ecparams.n)).mod(ecparams.n);
    //console.log("getSBuff m",bufferToHexString(mBig.toBuffer(ByteLenOfSk)));
    return retBig.toBuffer(ByteLenOfSk);
}

// return: buffer
function computeM1(M) {
	
	  //console.log("before hash(plainText)",bufferToHexString(M));	
    let M1 = h(M);
    //console.log("after hash(plainText)",bufferToHexString(M1));
    return M1;
}

// compute m
// M1=hash(M)
// m=hash(M1||R)
// M: buffer
// R: buffer
// return: buffer
function computem(M1, R) {
    let list = [];
    list.push(M1);
    list.push(R.slice(1));
    // hash(M1||R)
    let m = Buffer.concat(list);
    //console.log("before hash(M1||R)",bufferToHexString(m));    
    //console.log("after hash(M1||R)",bufferToHexString(h(m)));
    return h(m)
}

//typesArray:['uint256','string']
//parameters: ['2345675643', 'Hello!%']
//return : buff
function computeM(typesArray, parameters) {   
    let mStrHex = Web3EthAbi.encodeParameters(typesArray, parameters);
    return new Buffer(mStrHex.substring(2), 'hex');
}

// return : hexString
function getR() {
    return "0x" + R.toString('hex');
}

// return: hexString
function bufferToHexString(buff) {
    return "0x" + buff.toString('hex');
}

// sk: buff
// return: hexString
function getPKBySk(sk) {
    return bufferToHexString(baseScarMulti(sk));
}

//typesArray:['uint256','string']
//parameters: ['2345675643', 'Hello!%']
//return :hexString
function getS(sk, typesArray, parameters) {
    let MBuff = computeM(typesArray, parameters);
    let M1Buff = computeM1(MBuff);
    let mBuff = computem(M1Buff, R);
    let sBuff = getSBuff(sk, mBuff);
    return bufferToHexString(sBuff);
}

function getSByRawMsg(sk, rawMsg) {
    //let MBuff = new Buffer(removePrefix(rawMsg), 'hex'); 
    
    let MBuff = Buffer.from(rawMsg, 'utf8');    
    let M1Buff = computeM1(MBuff);  
    let mBuff = computem(M1Buff, R);    
    let sBuff = getSBuff(sk, mBuff);
    return bufferToHexString(sBuff);
}

function isHexString(hexStr) {
    let str = removePrefix(hexStr);
    if (str.length == 0) {
        return false;
    }
    return /^[A-Fa-f0-9]+$/.test(str) && str.length % 2 == 0;
}

//  random      :hexstring
//  sigS        :hexstring
//  rawMessage  :hexstring
//  pk          :hexstring
// return true,false
function verifySig(random, sigS, rawMessage, pk) {		
	
    if (!isHexString(random)) {
        throw "random:" + ErrInvalidHexString;
    }
    if (!isHexString(sigS)) {
        throw "sigS:" + ErrInvalidHexString;
    }    
    if (!isHexString(pk)) {
        throw "pk:" + ErrInvalidHexString;
    }
    // compute  left sG
    let sBuffer = new Buffer(removePrefix(sigS), 'hex');
    let left = baseScarMultiPt(sBuffer);       

    // compute  right R+m*pk
    let ptR;
    ptR = ptFromHex(random);
    let isOnCurve = ecparams.isOnCurve(ptR);
    if (!isOnCurve) {
        throw "random:" + ErrPointNotOnCurve;
    }

    let ptMPk;
    ptMPk = ptFromHex(pk);
    isOnCurve = ecparams.isOnCurve(ptMPk);
    if (!isOnCurve) {
        throw "pk:" + ErrPointNotOnCurve;
    }

    let bnm = getbnMFromRaw(random, rawMessage);    
     
    ptMPk = ptMPk.multiply(bnm);   

    let right;
    right = ptR.add(ptMPk);

    isOnCurve = ecparams.isOnCurve(left);
    if (!isOnCurve) {
        throw "left sG:" + ErrPointNotOnCurve;
    }
    isOnCurve = ecparams.isOnCurve(right);
    if (!isOnCurve) {
        throw "right R+m*PK:" + ErrPointNotOnCurve;
    }
    return left.equals(right);
}

function getbnMFromRaw(random, rawMsg) {
    
    let mBuff = getbnMFromRawBuff(random,rawMsg);
    return BigInteger.fromBuffer(mBuff);
}

function getbnMFromRawBuff(random, rawMsg) {
    let bufRandom = new Buffer(removePrefix(random), 'hex');   
    let bufRawMsg = new Buffer(rawMsg, 'utf-8');

    let M1Buff = computeM1(bufRawMsg);   
    let mBuff = computem(M1Buff, bufRandom);
    return mBuff;    
}

function getbnM1FromRawHexStr(random, rawMsg) {
    let bufRandom = new Buffer(removePrefix(random), 'hex');
    let bufRawMsg = new Buffer(removePrefix(rawMsg), 'hex');
    let M1Buff = computeM1(bufRawMsg);
    return bufferToHexString(M1Buff);
}


function ptFromHex(hexStr) {
    let hexStrTemp = removePrefix(hexStr);
    let bnX, bnY;
    if (hexStrTemp.length !== LenPtHexString) {
        throw ErrInvalidHexStringLen;
    }
    bnX = BigInteger.fromBuffer(new Buffer(hexStrTemp.substring(2, 66), 'hex'));
    bnY = BigInteger.fromBuffer(new Buffer(hexStrTemp.substring(66, LenPtHexString), 'hex'));
    
    return Point.fromAffine(ecparams, bnX, bnY);
}

function removePrefix(hexStr) {
    if (hexStr.length < 2) throw ErrInvalidHexString;
    if (hexStr.substring(0, 2) === "0x" || hexStr.substring(0, 2) === "0X") {
        return hexStr.substring(2);
    } else {
        return hexStr;
    }
}

module.exports = {    
    getPKBySk: getPKBySk,
    getR: getR,
    verifySig: verifySig,
    getSByRawMsg: getSByRawMsg,
    hashStr:hashStr,
    bufferToHexString:bufferToHexString,
    isHexString:isHexString,
};