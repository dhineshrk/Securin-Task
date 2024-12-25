const fetch = require('node-fetch');
const NodeCache = require('node-cache');

// Initialize cache with a default TTL of 60 minutes
const cache = new NodeCache({ stdTTL: 3600, checkperiod: 120 });

// Fetch CVEs with pagination and multiple filters
async function fetchCves(resultsPerPage, page, searchCveId, startDate, cvssScore) {
    // Ensure resultsPerPage is within a reasonable limit (for example, 20-100)
    resultsPerPage = Math.min(Math.max(resultsPerPage, 1), 100);  // Limit results per page to between 1 and 100

    const startIndex = (page - 1) * resultsPerPage; // Correctly calculate the start index for pagination
    let url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=${resultsPerPage}&startIndex=${startIndex}`;

    // Apply filters
    if (searchCveId) url += `&cveid=${searchCveId}`;
    if (cvssScore) url += `&minCvssScore=${cvssScore}`;

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

        // Filter CVEs by startDate (only published on the startDate)
        const filteredCves = data.vulnerabilities?.filter(v => {
            const publishedDate = new Date(v.cve.published).toISOString().split('T')[0]; // Parse and format published date
            console.log(publishedDate)
            console.log("first")
            // If the startDate filter is set, include only CVEs published on this date
            if (startDate) {
                const formattedStartDate = new Date(startDate).toISOString().split('T')[0];
                console.log(formattedStartDate)
                if (publishedDate !== formattedStartDate) {
                    return false; // Filter out CVEs not published on the startDate
                }
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
            cvssScore: v.cve.metrics.cvssMetricV2 && v.cve.metrics.cvssMetricV2[0].cvssData.baseScore || 'N/A',
        }));
        // console.log(cveList);
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

// Fetch CVEs by a specific start date
async function fetchCvesByDate(startDate, resultsPerPage = 20, page = 1) {
    const cacheKey = `cves_by_date_${startDate}_${resultsPerPage}_${page}`;
    const cachedData = cache.get(cacheKey);
    if (cachedData) {
        return cachedData;
    }

    // Ensure resultsPerPage is within a reasonable limit (for example, 20-100)
    resultsPerPage = Math.min(Math.max(resultsPerPage, 1), 100);  // Limit results per page to between 1 and 100

    const startIndex = (page - 1) * resultsPerPage; // Correctly calculate the start index for pagination
    let url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=${resultsPerPage}&startIndex=${startIndex}`;

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

        // Filter CVEs by startDate (only published on the startDate)
        const filteredCves = data.vulnerabilities?.filter(v => {
            const publishedDate = new Date(v.cve.published).toISOString().split('T')[0]; // Parse and format published date

            // If the startDate filter is set, include only CVEs published on this date
            const formattedStartDate = new Date(startDate).toISOString().split('T')[0];
            return publishedDate === formattedStartDate;
        }) || [];

        // Map the filtered data to the desired format
        const cveList = filteredCves.map(v => ({
            cveId: v.cve.id || 'N/A',
            publishedDate: v.cve.published || 'N/A',
            lastModified: v.cve.lastModified || 'N/A',
            vulnStatus: v.cve.vulnStatus || 'N/A',
            sourceIdentifier: v.cve.sourceIdentifier || 'N/A',
            cvssScore: v.cve.metrics.cvssMetricV2 && v.cve.metrics.cvssMetricV2[0].cvssData.baseScore || 'N/A',
        }));

        // Cache the result for future use
        cache.set(cacheKey, cveList);
        return cveList;
    } catch (error) {
        console.error('Error in fetchCvesByDate function:', error.message);
        throw error;
    }
}

module.exports = { fetchCves, fetchCveById, fetchCvesByDate };
