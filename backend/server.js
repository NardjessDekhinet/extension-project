const express = require("express");
const app = express();
const port = 3000;

// Simple test API
app.get("/", (req, res) => {
    res.send("Backend is running! CI/CD & Docker works 🚀");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
