const express = require("express");
const app = express();
const port = 3000;

// Simple test API

app.get("/", (req, res) => {
  res.json({ message: "New version deployed via CI/CD!" });

});




app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
