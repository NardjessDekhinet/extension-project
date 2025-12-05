// server.js
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.json({ message: 'testtt' });
});

// Only start server if not in test
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Server running on port ${port}`));
}

module.exports = app;
