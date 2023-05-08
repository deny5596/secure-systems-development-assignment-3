const net = require("net");
const crypto = require("crypto");
const Long = require("long");
const dns = require("dns");

// Constants
const MAGIC_BYTES = Buffer.from("0xD9B4BEF9", "hex");
const COMMAND_LENGTH = 12;
const PAYLOAD_LENGTH = 4;
const CHECKSUM_LENGTH = 4;

// Bitcoin message types
const MESSAGE_TYPES = {
  VERSION: "version",
  VERACK: "verack",
  BLOCK: "block",
  TX: "tx",
};

// Function to parse the block data from the payload
const parseBlockData = (payload) => {
  const blockHash = payload.slice(0, 32).toString("hex");
  const nonce = payload.slice(32, 40).toString("hex");
  const difficulty = payload.readUInt32LE(40);
  const transactions = [];
  let offset = 44;

  while (offset < payload.length) {
    const transactionHash = payload.slice(offset, offset + 32).toString("hex");
    const value = payload.readUInt32LE(offset + 32);
    transactions.push({ hash: transactionHash, value });
    offset += 36; // Increment offset to the next transaction
  }

  return { hash: blockHash, nonce, difficulty, transactions };
};

// Function to parse the transaction data from the payload
// Parse the transaction data
const parseTransactionData = (payload) => {
  const version = payload.readUInt32LE(0); // Transaction version
  const inputCountVarInt = readVarInt(payload, 4); // Number of transaction inputs
  const inputCount = inputCountVarInt.value;
  let offset = inputCountVarInt.size + 4;

  // Parse transaction inputs
  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const prevTxHash = payload.slice(offset, offset + 32).toString("hex"); // Previous transaction hash
    offset += 32;
    const prevTxOutputIndex = payload.readUInt32LE(offset); // Previous transaction output index
    offset += 4;
    const scriptLengthVarInt = readVarInt(payload, offset); // Length of the input script
    const scriptLength = scriptLengthVarInt.value;
    offset += scriptLengthVarInt.size;
    const scriptSig = payload
      .slice(offset, offset + scriptLength)
      .toString("hex"); // Input script
    offset += scriptLength;
    const sequence = payload.readUInt32LE(offset); // Sequence number
    offset += 4;

    const input = {
      prevTxHash,
      prevTxOutputIndex,
      scriptSig,
      sequence,
    };

    inputs.push(input);
  }

  const outputCountVarInt = readVarInt(payload, offset); // Number of transaction outputs
  const outputCount = outputCountVarInt.value;
  offset += outputCountVarInt.size;

  // Parse transaction outputs
  const outputs = [];
  for (let i = 0; i < outputCount; i++) {
    const value = payload.readBigUInt64LE(offset); // Output value
    offset += 8;
    const scriptLengthVarInt = readVarInt(payload, offset); // Length of the output script
    const scriptLength = scriptLengthVarInt.value;
    offset += scriptLengthVarInt.size;
    const scriptPubKey = payload
      .slice(offset, offset + scriptLength)
      .toString("hex"); // Output script
    offset += scriptLength;

    const output = {
      value,
      scriptPubKey,
    };

    outputs.push(output);
  }

  const lockTime = payload.readUInt32LE(offset); // Transaction lock time

  const transactionData = {
    version,
    inputs,
    outputs,
    lockTime,
  };

  return transactionData;
};

// Read a 32-bit unsigned integer from the payload at the specified offset
const readUInt32LE = (payload, offset) => {
  return payload.readUInt32LE(offset);
};

// Read a variable-length integer from the payload
const readVarInt = (payload, offset) => {
  const prefix = payload.readUInt8(offset);

  if (prefix < 0xfd) {
    return {
      value: prefix,
      size: 1,
    };
  } else if (prefix === 0xfd) {
    return {
      value: payload.readUInt16LE(offset + 1),
      size: 3,
    };
  } else if (prefix === 0xfe) {
    return {
      value: payload.readUInt32LE(offset + 1),
      size: 5,
    };
  } else {
    return {
      value: payload.readBigUInt64LE(offset + 1),
      size: 9,
    };
  }
};

// Connect to a Bitcoin node
const connectToNode = (ip, port) => {
  const socket = net.connect(port, ip, () => {
    console.log(`Connected to Bitcoin node: ${ip}:${port}`);

    // Send the version payload to the node
    sendVersionPayload(socket);
  });

  // Handle data received from the node
  socket.on("data", (data) => parseBitcoinMessage(data, socket));

  // Handle socket errors
  socket.on("error", (error) => {
    console.error(`Socket error: ${error.message}`);
  });

  // Handle socket disconnection
  socket.on("close", () => {
    console.log(`Disconnected from Bitcoin node: ${ip}:${port}`);
  });

  return socket;
};

// Parse a Bitcoin message
const parseBitcoinMessage = (data, socket) => {
  let offset = 0;

  // Parse the magic bytes
  const magicBytes = data.slice(offset, offset + 4);

  offset += 4;

  if (!magicBytes.equals(MAGIC_BYTES)) {
    console.error("Invalid magic bytes");
    return;
  }

  // Parse the command
  const command = data
    .slice(offset, offset + COMMAND_LENGTH)
    .toString("utf8")
    .replace(/\0/g, "");
  offset += COMMAND_LENGTH;

  // Parse the payload length
  const payloadLength = data.readUInt32LE(offset);
  offset += PAYLOAD_LENGTH;

  // Parse the checksum
  const checksum = data.slice(offset, offset + CHECKSUM_LENGTH);
  offset += CHECKSUM_LENGTH;

  // Verify the checksum
  const payload = data.slice(offset, offset + payloadLength);
  const calculatedChecksum = crypto
    .createHash("sha256")
    .update(payload)
    .digest()
    .slice(0, 4);

  if (!checksum.equals(calculatedChecksum)) {
    console.error("Invalid checksum");
    return;
  }

  // Handle different message types
  switch (command) {
    case MESSAGE_TYPES.VERSION:
      handleVersionMessage(payload, socket);
      break;
    case MESSAGE_TYPES.VERACK:
      handleVerackMessage(socket);
      break;
    case MESSAGE_TYPES.BLOCK:
      handleBlockMessage(payload);
      break;
    case MESSAGE_TYPES.TX:
      handleTransactionMessage(payload);
      break;
    // Handle other message types as needed
  }
};

// Handle a block message
const handleBlockMessage = (payload) => {
  let offset = 0;

  // Parse the block header
  const version = payload.readUInt32LE(offset);
  offset += 4;

  const previousBlockHash = payload.slice(offset, offset + 32).toString("hex");
  offset += 32;

  const merkleRoot = payload.slice(offset, offset + 32).toString("hex");
  offset += 32;

  const timestamp = new Date(payload.readUInt32LE(offset) * 1000).toUTCString();
  offset += 4;

  const bits = payload.readUInt32LE(offset);
  offset += 4;

  const nonce = payload.readUInt32LE(offset);
  offset += 4;

  console.log("Block Header:");
  console.log("--------------");
  console.log("Version:", version);
  console.log("Previous Block Hash:", previousBlockHash);
  console.log("Merkle Root:", merkleRoot);
  console.log("Timestamp:", timestamp);
  console.log("Bits:", bits);
  console.log("Nonce:", nonce);

  // Parse the transaction count
  const transactionCount = readVarInt(payload, offset);
  offset += transactionCount.size;

  console.log("\nTransactions:");
  console.log("-------------");
  console.log("Transaction Count:", transactionCount.value);

  // Parse individual transactions
  for (let i = 0; i < transactionCount.value; i++) {
    const transaction = parseTransactionData(payload.slice(offset));
    offset += transaction.size;

    console.log("\nTransaction", i + 1);
    console.log("----------------");
    console.log("Version:", transaction.version);
    console.log("Transaction Hash:", transaction.transactionHash);
    console.log("Input Count:", transaction.inputCount);
    console.log("Output Count:", transaction.outputCount);
    console.log("Lock Time:", transaction.lockTime);

    // Display transaction inputs
    console.log("Inputs:");
    for (let j = 0; j < transaction.inputs.length; j++) {
      const input = transaction.inputs[j];
      console.log("- Input", j + 1);
      console.log(
        "  Previous Transaction Hash:",
        input.previousTransactionHash
      );
      console.log(
        "  Previous Transaction Output Index:",
        input.previousOutputIndex
      );
      console.log("  Script Length:", input.scriptLength);
      console.log("  Script Signature:", input.scriptSignature);
      console.log("  Sequence Number:", input.sequenceNumber);
    }

    // Display transaction outputs
    console.log("Outputs:");
    for (let j = 0; j < transaction.outputs.length; j++) {
      const output = transaction.outputs[j];
      console.log("- Output", j + 1);
      console.log("  Value:", output.value);
      console.log("  Script Length:", output.scriptLength);
      console.log("  Script:", output.script);
    }
  }
};

// Handle a transaction message
const handleTransactionMessage = (payload) => {
  // Parse the transaction data
  const version = payload.readUInt32LE(0);
  let offset = 5;

  offset += readVarInt(payload, offset).size;

  const lockTime = payload.readUInt32LE(offset);

  // Display the transaction details
  console.log("Transaction Details:");
  console.log(`Version: ${version}`);
  console.log(`Lock Time: ${lockTime}`);
};

// Start the program by connecting to Bitcoin nodes
const startProgram = () => {
  // Seed nodes for getting IPs of Bitcoin nodes
  const seedNodes = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
  ];

  seedNodes.forEach((node) => {
    dns.resolve(node, (err, addresses) => {
      if (err) {
        console.error(`Failed to resolve DNS for ${node}: ${err.message}`);
        return;
      }

      addresses.forEach((address) => {
        // Default Bitcoin port is 8333
        const socket = connectToNode(address, 8333);

        socket.on("connect", () => {
          console.log(`Connected to Bitcoin node: ${address}`);
        });
      });
    });
  });
};

// Send the version payload to the node
const sendVersionPayload = (socket) => {
  const version = 70015; // Your version number
  const services = 0; // Your supported services (set to 0 for now)
  const timestamp = Math.floor(Date.now() / 1000); // Current timestamp
  const addrRecvServices = 0; // Services provided by the receiving node
  const addrRecvIP = "0.0.0.0"; // IP address of the receiving node
  const addrRecvPort = 8333; // Port of the receiving node
  const addrTransServices = 0; // Services provided by the transmitting node
  const addrTransIP = "0.0.0.0"; // IP address of the transmitting node
  const addrTransPort = 8333; // Port of the transmitting node
  const nonce = Buffer.alloc(8); // Nonce (set to empty buffer for now)
  const userAgentBytes = Buffer.from("/MyBitcoinExplorerApp:1.0.0/");
  const startHeight = 0; // Block height of the transmitting node
  const relay = 0; // Whether to relay transactions (set to 0 for now)

  // Construct the version message payload
  const payload = Buffer.concat([
    Buffer.from([version]),
    Buffer.from([services]),
    Buffer.from(Long.fromNumber(timestamp).toBytesLE()),
    Buffer.from([addrRecvServices]),
    Buffer.from(addrRecvIP.split(".").map(Number)),
    Buffer.from(addrRecvPort.toString(16), "hex"),
    Buffer.from([addrTransServices]),
    Buffer.from(addrTransIP.split(".").map(Number)),
    Buffer.from(addrTransPort.toString(16), "hex"),
    nonce,
    Buffer.from([userAgentBytes.length]),
    userAgentBytes,
    Buffer.from(Long.fromNumber(startHeight).toBytesLE()),
    Buffer.from([relay]),
  ]);

  // Send the version message
  sendMessage(socket, MESSAGE_TYPES.VERSION, payload);
};

// Handle a version message
const handleVersionMessage = (payload, socket) => {
  console.log("Received version payload:", payload.toString("hex"));

  // Send the verack payload
  sendVerackPayload(socket);
};

// Send the verack payload to the node
const sendVerackPayload = (socket) => {
  const payload = Buffer.alloc(0);

  sendMessage(socket, MESSAGE_TYPES.VERACK, payload);
};

// Handle a verack message
const handleVerackMessage = (socket) => {
  console.log("Received verack payload");

  // Send the verack payload back to the node
  sendVerackPayload(socket);
};

// Send a Bitcoin message
const sendMessage = (socket, command, payload) => {
  const commandBuffer = Buffer.alloc(COMMAND_LENGTH);
  commandBuffer.write(command, "utf8");

  const payloadLengthBuffer = Buffer.alloc(PAYLOAD_LENGTH);
  payloadLengthBuffer.writeUInt32LE(payload.length);

  const checksum = crypto.createHash("sha256").update(payload).digest();
  const doubleChecksum = crypto.createHash("sha256").update(checksum).digest();
  const checksumBuffer = doubleChecksum.slice(0, CHECKSUM_LENGTH);

  const message = Buffer.concat([
    MAGIC_BYTES,
    commandBuffer,
    payloadLengthBuffer,
    checksumBuffer,
    payload,
  ]);

  socket.write(message);
};

// Start the program
startProgram();
