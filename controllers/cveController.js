const fetch = require('node-fetch');
const NodeCache = require('node-cache');
const { base } = require('../models/cveModel');

// Initialize cache with a default TTL of 60 minutes
const cache = new NodeCache({ stdTTL: 3600, checkperiod: 120 });

// Fetch CVEs with pagination and multiple filters
// Fetch CVEs with pagination and multiple filters
async function fetchCves(resultsPerPage, page, searchCveId, startDate, cvssScore) {
    // console.log(parseFloat(cvssScore))
    // Ensure resultsPerPage is within a reasonable limit (for example, 20-100)
    resultsPerPage = Math.min(Math.max(resultsPerPage, 1), 100);  // Limit results per page to between 1 and 100

    const startIndex = (page - 1) * resultsPerPage; // Correctly calculate the start index for pagination
    let url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=${resultsPerPage}&startIndex=${startIndex}`;

    // Apply filters
    if (searchCveId) url += `&cveid=${searchCveId}`;
    // const baseScore = data.vulnerabilities.cve.metrics.cvssMetricV2?.[0]?.cvssData?.baseScore;

    try {
        const response = await fetch(url);

        // Check if the response is not a JSON (i.e., HTML error page)
        if (response.headers.get('content-type').includes('text/html')) {
            const htmlError = await response.text();
            console.error('Received HTML error:', htmlError);
            throw new Error('Received HTML error response, not JSON');
        }

        // Parse response as JSON
        const data = await response.json();

        // Check if 'vulnerabilities' exists in the response
        if (!data.vulnerabilities) {
            return []; // Return an empty array if no vulnerabilities are found
        }

        // Filter CVEs by startDate and cvssScore
        const filteredCves = data.vulnerabilities?.filter(v => {
            const publishedDate = new Date(v.cve.published);
            publishedDate.setHours(0, 0, 0, 0); // Set time to midnight for comparison

            const baseScore = v.cve.metrics.cvssMetricV2?.[0]?.cvssData?.baseScore;
            // console.log(baseScore)
            // console.log("cvss")
            // console.log(parseFloat(cvssScore))

            // Filter by startDate
            if (startDate) {
                const formattedStartDate = new Date(startDate);
                formattedStartDate.setHours(0, 0, 0, 0); // Set time to midnight

                if (publishedDate.getTime() !== formattedStartDate.getTime()) {
                    return false; // Filter out CVEs not published on the startDate
                }
            }

            // Filter by cvssScore (exact match)
            
            if (cvssScore && baseScore !== cvssScore) {
                // console.log(cvssScore)
                return false;
            }
            return true;
        }) || [];

        // Map the filtered data to the desired format
        const cveList = filteredCves.map(v => ({
            cveId: v.cve.id || 'N/A',
            publishedDate: v.cve.published || 'N/A',
            lastModified: v.cve.lastModified || 'N/A',
            vulnStatus: v.cve.vulnStatus || 'N/A',
            sourceIdentifier: v.cve.sourceIdentifier || 'N/A',
            baseScore: v.cve.metrics.cvssMetricV2?.[0]?.cvssData?.baseScore || 'N/A',
        }));
        // console.log(Number(cvssScore))

        return cveList;
    } catch (error) {
        console.error('Error in fetchCves function:', error.message);
        throw error;
    }
}


// Fetch specific CVE by ID
async function fetchCveById(cveId) {
    const cacheKey = `cve_${cveId}`;
    const cachedData = cache.get(cacheKey);
    if (cachedData) {
        return cachedData;
    }

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;

    try {
        const response = await fetch(url);

        // Check if the response is not a JSON (i.e., HTML error page)
        if (response.headers.get('content-type').includes('text/html')) {
            const htmlError = await response.text();
            console.error('Received HTML error:', htmlError);
            throw new Error('Received HTML error response, not JSON');
        }

        if (response.status === 404) {
            return null;
        }

        if (!response.ok) {
            throw new Error(`Failed to fetch data from NVD: ${response.statusText}`);
        }

        const data = await response.json();
        const cveDetails = data.vulnerabilities?.[0]?.cve;

        if (!cveDetails) {
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
