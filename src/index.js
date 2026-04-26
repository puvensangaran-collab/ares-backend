require('dotenv').config();
const express = require('express');
const app = express();
app.use(express.json());
app.get('/', (req, res) => res.json({ status: 'Ares backend running' }));
app.listen(process.env.PORT || 3000);
