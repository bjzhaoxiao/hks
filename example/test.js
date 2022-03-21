const schnorr = require('./tools');
const sk = new Buffer("7a077a31d1f288a43dd3d02a2a239b21dcad28b2a4f306a1325937e505bb1700", 'hex');
const  userAddr = "0x1d001bd18a85e9830bf45047700edae5717340bc"


const Web3=require("web3");

const abi=[{"constant":false,"inputs":[{"name":"signature","type":"bytes32"},{"name":"groupKeyX","type":"bytes32"},{"name":"groupKeyY","type":"bytes32"},{"name":"randomPointX","type":"bytes32"},{"name":"randomPointY","type":"bytes32"},{"name":"message","type":"bytes32"}],"name":"verify","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"x","type":"uint256"},{"name":"y","type":"uint256"},{"name":"scalar","type":"uint256"}],"name":"cmul","outputs":[{"name":"","type":"uint256"},{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getGx","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"ax","type":"uint256"},{"name":"ay","type":"uint256"},{"name":"bx","type":"uint256"},{"name":"by","type":"uint256"}],"name":"cadd","outputs":[{"name":"","type":"uint256"},{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"x1","type":"uint256"},{"name":"y1","type":"uint256"},{"name":"scalar","type":"uint256"}],"name":"ecmul","outputs":[{"name":"x2","type":"uint256"},{"name":"y2","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getGy","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"x1","type":"uint256"},{"name":"y1","type":"uint256"},{"name":"x2","type":"uint256"},{"name":"y2","type":"uint256"}],"name":"ecadd","outputs":[{"name":"x3","type":"uint256"},{"name":"y3","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getOrder","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"sig_s","type":"uint256"}],"name":"sg","outputs":[{"name":"","type":"uint256"},{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"m","type":"bytes32"},{"name":"a","type":"uint256"},{"name":"b","type":"uint256"}],"name":"h","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"}];

let testnet = true;
let scAddr,url,chainId;

if(testnet){
	scAddr="0xCEF0a0D9F47267847a25C59437BCF9A65Cbaf567";		
	url="https://api.avax-test.network/ext/bc/C/rpc";
	chainId = 43113;
}else{
	scAddr="";		
	url="";
	chainId = 43114;
}

async function test() {
	  // create sig  
    console.log("\n\n===================Create sig=====================\n\n");    
    
    let rawMsg = await getInput("Input message for schnorr signature \nexample:hello avalanche\n") || "hello avalanche";
    rawMsg = rawMsg.trim();
    
    console.log("rawMsg:\t\t",rawMsg);
    
    let rawMsgHashHex = schnorr.hashStr(rawMsg);
    console.log("hash(rawMsg):\t",rawMsgHashHex);
    
    let pk = schnorr.getPKBySk(sk);
    console.log("pk:\t\t",pk);    
    
    let sByRaw = schnorr.getSByRawMsg(sk, rawMsg);
    console.log("schnorr s:\t",sByRaw);
      
    let R = schnorr.getR();
    console.log("schnorr R:\t",R);    
    
    // verify sig by local
//    console.log("\n\n===================Verify sig =====================\n\n");
//    try {
//        let ret = schnorr.verifySig(R, sByRaw, rawMsg, pk);
//        if (ret) {
//            console.log("verifySig success");
//        } else {
//            console.log("verifySig fail");
//        }
//    } catch (err) {
//        console.log("verifySig fail");
//        console.log(err.toString());
//    }
    
    // verify sig by contract
    console.log("\n\n===================Verify sig by contract ===========\n\n");
    try{
    		let web3 = new Web3(url);

     		let c = await new web3.eth.Contract(abi,scAddr);
     		
     		let valid = false;
     		while(true)
     		{
     				sByRaw =  await getInput("Input signature(s) \nexample:0x1573a12a164f48838f2280ff73cf387325380952593d00688a53fc3743297d47\n") || "0x1573a12a164f48838f2280ff73cf387325380952593d00688a53fc3743297d47";
     				if(!schnorr.isHexString(sByRaw)){
     					console.log("Not hex string");
     					continue;	
     				}     				
     				
     				if(sByRaw.length != 66){
     					console.log("Length is not right");
     					continue;	
     				}
     				break;
     		}		
     		

     		let data = await c.methods.verify(sByRaw,"0x"+pk.slice(4,68),"0x"+pk.slice(68,132),"0x"+R.slice(4,68),"0x"+R.slice(68,132),rawMsgHashHex).encodeABI()
     		
     		
     		console.log("sByRaw:\t\t",sByRaw);
     		console.log("R.x:\t\t","0x"+R.slice(4,68));
     		console.log("R.y:\t\t","0x"+R.slice(68,132));
     		
     		console.log("pk.x:\t\t","0x"+pk.slice(4,68));
     		console.log("pk.y:\t\t","0x"+pk.slice(68,132));
     		
     		console.log("rawMsgHashHex:\t",rawMsgHashHex);
     
     		let tx = {
			   				from:userAddr,
						    to: scAddr,
						    value: 0x00,
						    gas: await web3.eth.estimateGas({to:scAddr,data:data}),
						    gasPrice: await web3.eth.getGasPrice(),
						    nonce: await web3.eth.getTransactionCount(userAddr),
						    chainId: chainId,
						    data: data,
					}				
					
			   	let ret = await web3.eth.accounts.signTransaction(tx, schnorr.bufferToHexString(sk));				
					let rcpt = await sendTrans(web3,ret.rawTransaction);
					if(rcpt.status){
						console.log("txHash:\t\t",rcpt.transactionHash);
						console.log("verifySig by contract success");
					}					
    	
    } catch (err)
    {
    		console.log("verifySig by contract fail");
        console.log(err.toString());
    }
     
    
}


async function sendTrans(web3,data){
		let rep = await web3.eth.sendSignedTransaction(data)
		return rep
}



function getInput(promptStr){
    return new Promise((resolve, reject) => {
        var read = require('read');
        read({ prompt: promptStr, silent: false }, function(err, password) {
            if(err != null){
                reject(err);
            }else{
                resolve(password);
            }
        })
    });
}


test();