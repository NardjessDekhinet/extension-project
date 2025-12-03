const express = require("express");
const app = express();
const port = 3000;

// Simple test API

app.get('/', (req, res) => {
  res.send('Web Extension DevOps Demo is Running 🚀 - Updated Version!');
});
console.log("CI/CD workflow test!");



app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
