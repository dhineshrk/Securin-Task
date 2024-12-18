const axios = require('axios');
const mongoose = require('mongoose');
const CVE = require('../models/cveModel');// CVE Model

// NVD API base URL
const API_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// MongoDB connection setup
const connectToDatabase = async () => {
  try {
    await mongoose.connect('mongodb://localhost:27017/cveDB', { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('Connected to the database');
  } catch (error) {
    console.error('Database connection error:', error);
  }
};

// Function to fetch CVE data from the NVD API with pagination
const fetchCVEData = async (startIndex = 0, resultsPerPage = 10) => {
  try {
    const response = await axios.get(`${API_BASE_URL}?startIndex=${startIndex}&resultsPerPage=${resultsPerPage}`);
    return response.data;
  } catch (error) {
    console.error('Error fetching CVE data:', error);
    return null;
  }
};

// Function to sync CVE data into the MongoDB database
const syncCVEData = async (startIndex = 0, resultsPerPage = 10) => {
  const cveData = await fetchCVEData(startIndex, resultsPerPage);

  if (!cveData || !cveData.result || !cveData.result.CVE_Items) {
    console.log('No CVE data to process');
    return;
  }

  const cveItems = cveData.result.CVE_Items;

  for (let cve of cveItems) {
    const cveId = cve.cve.CVE_data_meta.ID;
    const description = cve.cve.descriptions.map(desc => desc.value).join(' ');

    const existingCVE = await CVE.findOne({ cveId });

    if (existingCVE) {
      existingCVE.description = description;
      existingCVE.lastModified = new Date();
      await existingCVE.save();
      console.log(`Updated CVE: ${cveId}`);
    } else {
      const newCVE = new CVE({
        cveId,
        description,
        publishedDate: new Date(cve.publishedDate),
        lastModified: new Date(),
      });
      await newCVE.save();
      console.log(`Created new CVE: ${cveId}`);
    }
  }
};

// Function to synchronize data in smaller chunks
const syncDataInChunks = async () => {
  const resultsPerPage = 10;
  let startIndex = 0;
  const batchSize = 100; // Process in chunks of 100 records at a time

  while (true) {
    console.log(`Syncing from index ${startIndex}`);
    await syncCVEData(startIndex, resultsPerPage);

    startIndex += resultsPerPage;
    // Break if fewer than resultsPerPage records are fetched (end of available data)
    if (startIndex >= 1000) break;
  }
};

// Sync process every day
const syncDataPeriodically = () => {
  setInterval(async () => {
    console.log('Syncing CVE data...');
    await syncDataInChunks(); // Sync in smaller chunks
  }, 24 * 60 * 60 * 1000); // Sync every 24 hours
};

// Start sync process
const startSync = async () => {
  await connectToDatabase();
  await syncDataPeriodically();
};

startSync();
