const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');
const connectDB = require('./config/db');
const cveRoutes = require('./routes/cveRoutes');
const cors = require('cors');
// Enable CORS for all routes


dotenv.config();

const app = express();
connectDB();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));  // Serve frontend files

app.use('/cves', cveRoutes);
app.use(cors()); 
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
