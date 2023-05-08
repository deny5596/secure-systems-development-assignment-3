const axios = require("axios");
const crypto = require("crypto");

function calculateBlockHash(blockData) {
  const stringifiedBlockData = JSON.stringify(blockData);
  // Convert the block data to a Buffer
  const blockBuffer = Buffer.from(stringifiedBlockData, "utf8");
  // Calculate the SHA-256 hash
  const sha256Hash = crypto.createHash("sha256").update(blockBuffer).digest();
  // Calculate the double SHA-256 hash
  const doubleSha256Hash = crypto
    .createHash("sha256")
    .update(sha256Hash)
    .digest();
  // Convert the hash to a hexadecimal string
  const hash = doubleSha256Hash.toString("hex");

  return hash;
}

function getBlockChainData() {
  axios
    .get("https://blockchain.info/latestblock")
    .then((response) =>
      axios.get(`https://blockchain.info/rawblock/${response.data.hash}`)
    )
    .then(async (response) => {
      const { data } = await axios.get(
        "https://blockchain.info/q/getdifficulty"
      );

      return {
        difficulty: data,
        blockChainData: response.data,
      };
    })
    .then((data) => {
      // Extract relevant block information
      const { blockChainData, difficulty } = data;
      const { time, tx, nonce, hash } = blockChainData;

      blockChainData.difficulty = difficulty;

      // Format the timestamp to a human-readable form
      const date = new Date(time * 1000); // Convert timestamp to milliseconds
      const formattedDate = date.toLocaleString("en-US", {
        month: "long",
        day: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "numeric",
      });

      // Display the block information
      console.log("Block added to the blockchain on:", formattedDate);
      console.log("Transactions in the block:");
      tx.forEach((transaction, index) => {
        // console.log(transaction);
        console.log(`Transaction ${index + 1}: ${transaction.hash}`);
        console.log("Value:", transaction.out[0]["value"]);
      });
      console.log("Nonce:", nonce);
      console.log("Difficulty Level:", difficulty);

      // Verify the hash
      const calculatedHash = calculateBlockHash(blockChainData);
      console.log("Original Hash:", hash);
      console.log("Calculated Hash:", calculatedHash);

      if (calculatedHash === hash) {
        console.log("The hash matches the hash included in the block.");
      } else {
        console.log("The hash does not match the hash included in the block.");
      }
    })
    .catch((error) => {
      console.error("An error occurred:", error);
    });
}
while (true) {
  getBlockChainData();
}
