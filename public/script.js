let currentPage = 1; // Start on the first page

// Function to display CVEs in a table
function displayCVEs(cves) {
    const tableBody = document.getElementById('cveTable').getElementsByTagName('tbody')[0];
    tableBody.innerHTML = ''; // Clear any existing rows

    if (!Array.isArray(cves) || cves.length === 0) {
        console.error('No CVE data available to display');
        return; // Exit if no data
    }

    const formatDate = (dateString) => {
        const date = new Date(dateString);
        const options = { day: '2-digit', month: 'short', year: 'numeric' };
        return !isNaN(date) ? date.toLocaleDateString('en-GB', options) : 'N/A';
    };

    cves.forEach((vulnerability) => {
        const row = document.createElement('tr');

        // Ensure we're getting the right properties
        const cveId = vulnerability.cveId || 'N/A';
        const sourceIdentifier = vulnerability.sourceIdentifier || 'N/A';
        const publishedDate = formatDate(vulnerability.publishedDate) || 'N/A';
        const modifiedDate = formatDate(vulnerability.lastModified) || 'N/A';
        const vulnStatus = vulnerability.vulnStatus || 'N/A';
        const cvssScore = vulnerability.baseScore;
        console.log(vulnerability)

        const createCellWithLink = (textContent, link) => {
            const cell = document.createElement('td');
            const anchor = document.createElement('a');
            anchor.href = link;
            anchor.textContent = textContent;
            anchor.style.textDecoration = 'none';
            anchor.style.color = 'black';
            cell.appendChild(anchor);
            return cell;
        };

        row.appendChild(createCellWithLink(cveId, `/cves/cve-detail/${cveId}`));
        row.appendChild(createCellWithLink(sourceIdentifier, `/cves/cve-detail/${cveId}`));
        row.appendChild(createCellWithLink(publishedDate, `/cves/cve-detail/${cveId}`));
        row.appendChild(createCellWithLink(modifiedDate, `/cves/cve-detail/${cveId}`));
        row.appendChild(createCellWithLink(vulnStatus, `/cves/cve-detail/${cveId}`));
        row.appendChild(createCellWithLink(cvssScore, `/cves/cve-detail/${cveId}`));

        tableBody.appendChild(row);
    });
}

// Function to load CVEs based on the current page and selected filters
async function loadCVEs(page = 1) {
    currentPage = page;

    const resultsPerPage = document.getElementById('resultsPerPage').value;
    const searchCveId = document.getElementById('searchCveId').value;
    const startDate = document.getElementById('startDate').value;
    const cvssScore = document.getElementById('cvssScore').value;

    try {
        const response = await fetch(`/cves/list?resultsPerPage=${resultsPerPage}&page=${page}&searchCveId=${searchCveId}&startDate=${startDate}&cvssScore=${cvssScore}`);
        if (!response.ok) { 
            throw new Error('Failed to fetch CVE data');
        }

        const data = await response.json();
        if (data && data.vulnerabilities) {
            document.getElementById('totalRecords').textContent = `Total Records: ${data.vulnerabilities.length}`;
            displayCVEs(data.vulnerabilities);
            document.getElementById('pageNumber').textContent = `Page ${currentPage}`;

            // Disable or enable pagination buttons
            document.getElementById('prevPage').disabled = currentPage === 1;
            document.getElementById('nextPage').disabled = data.vulnerabilities.length < resultsPerPage;
        } else {
            console.error('No CVE data received');
        }
    } catch (error) {
        console.error('Error fetching CVE data:', error);
    }
}

// Add event listener for the "Search" button
document.getElementById('searchButton').addEventListener('click', () => {
    currentPage = 1; // Reset to the first page when search is triggered
    loadCVEs(currentPage); // Load with the new filters
});

// Event listeners for previous and next page buttons
document.getElementById('prevPage').addEventListener('click', () => loadCVEs(currentPage - 1));
document.getElementById('nextPage').addEventListener('click', () => loadCVEs(currentPage + 1));

// Add event listener for results per page change
document.getElementById('resultsPerPage').addEventListener('change', () => {
    currentPage = 1; // Reset to the first page when the results per page changes
    loadCVEs(currentPage); // Load with the new page size
});

// Load initial CVEs when the page loads
loadCVEs();
