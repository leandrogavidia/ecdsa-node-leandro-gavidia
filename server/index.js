const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;
const utils = require("ethereum-cryptography/utils")
const keccak = require("ethereum-cryptography/keccak")
const secp = require("ethereum-cryptography/secp256k1");

app.use(cors());
app.use(express.json());

const balances = {
  "03daff9fdc7bf96daf944d95d6b8505ab4eb8f51b38dfcdbd04980d7d430958435": 100, // e5e23ce54f404ff8abe3eaa08071fbdf4506ab804cbef3d9f770af38376f003c
  "02e31b6a8fb386447b8f001062318cd4048d35cc547972ca0d2f299904340c5e15": 50, // dcab156e07e6210a31ad51b412c3b054f1303d8beeaef5d40fc4569408eb232b
  "028e5424df1490f55a28d9d19bcfb54c36909dfaeb090b1e187a090c9069e65490": 75, // 76c20462a89a75f5ed868561b7179a5c27a6dbc60397162c975d0a4fd8d78a6b
};

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  // SIGN A MESSAGE
  // 1.1: Message to Bytes - DONE
  // 1.2: Bytes to message - DONE
  // 1.3: Sign message with the user's private key, recovered: true - DONE

  // RECOVER ADDRESS
  // 2.1: Recover publicKey (msgHash, signature, recoveryBit)
  // 2.2: Remove first byte
  // 2.3: Hash publicKey
  // 2.4: Get last 20 bytes

  // TODO: get signature from the client-side application
  // recover the public address from the signature
   
  const { sender, recipient, amount, privateKey } = req.body;

  setInitialBalance(sender);
  setInitialBalance(recipient);

  const hashMessage = (msg) => {
    const msgBytes = utils.utf8ToBytes(msg)
    const msgHashed = keccak.keccak256(msgBytes)
    const msgHex = utils.toHex(msgHashed)
    return msgHex
  }

  const signMessage = (msg) => {
    const msgHex = hashMessage(msg)
    const signature = secp.secp256k1.sign(msgHex, privateKey)
    return signature
  }

  const createSignature = (msg) => {
    const msgHex = hashMessage(msg)
    const signature = signMessage(msg)
    return {
      message: msgHex,
      signature: signature
    }
  }

  const verifySignature = (pubkey, signature) => {
    const didMatch = secp.secp256k1.verify(signature.signature, signature.message, pubkey)
    return didMatch
  }

  const signature = createSignature("TRANSFER")
  const didMatch = verifySignature(sender, signature)
  
  if (!didMatch) {
    res.status(400).send({ message: "Signature doesn't match" }, JSON.stringify(signature));
  }
  else if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" }, JSON.stringify(balances[sender]));
  } 
  else {
    console.log("privateKey", didMatch)
    balances[sender] -= amount;
    balances[recipient] += amount;
    res.send({ balance: balances[sender] });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
