const fetch = require('node-fetch');
const NodeCache = require('node-cache');

// Initialize cache with a default TTL of 60 minutes
const cache = new NodeCache({ stdTTL: 3600, checkperiod: 120 });

// Fetch CVEs with pagination
async function fetchCves(resultsPerPage, page) {
    const startIndex = (page - 1) * resultsPerPage;
    const cacheKey = `cves_${resultsPerPage}_${page}`;

    const cachedData = cache.get(cacheKey);
    if (cachedData) {
        console.log(`Cache hit for: ${cacheKey}`);
        return cachedData;
    }

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=${resultsPerPage}&startIndex=${startIndex}`;

    try {
        console.log(`Fetching data from: ${url}`);
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to fetch data from NVD: ${response.statusText}`);
        }

        const data = await response.json();
        const cveList = data.vulnerabilities?.map(v => v.cve) || [];

        cache.set(cacheKey, cveList);
        return cveList;
    } catch (error) {
        console.error('Error in fetchCves function:', error.message);
        throw error;
    }
}

// Fetch specific CVE by ID
async function fetchCveById(cveId) {
    console.log(cveId)
    const cacheKey = `cve_${cveId}`;
    const cachedData = cache.get(cacheKey);
    if (cachedData) {
        console.log(`Cache hit for: ${cacheKey}`);
        return cachedData;
    }

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;

    try {
        console.log(`Fetching data from: ${url}`);
        const response = await fetch(url);
        console.log(response)
        if (response.status === 404) {
            console.error(`CVE ID not found: ${cveId}`);
            return null;
        }

        if (!response.ok) {
            throw new Error(`Failed to fetch data from NVD: ${response.statusText}`);
        }

        const data = await response.json();
        const cveDetails = data.vulnerabilities?.[0]?.cve;

        if (!cveDetails) {
            console.error(`CVE ID ${cveId} not found in API response.`);
            return null;
        }

        cache.set(cacheKey, cveDetails);
        return cveDetails;
    } catch (error) {
        console.error('Error in fetchCveById function:', error.message);
        throw error;
    }
}

module.exports = { fetchCves, fetchCveById };