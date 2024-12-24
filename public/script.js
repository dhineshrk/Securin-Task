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

    cves.forEach((vulnerability, index) => {
        if (!vulnerability.id) {
            console.warn(`Skipping entry at index ${index} due to missing CVE ID`);
            return;
        }

        const row = document.createElement('tr');
        const cveId = vulnerability.id || 'N/A';
        const sourceIdentifier = vulnerability.sourceIdentifier || 'N/A';
        const publishedDate = formatDate(vulnerability.published) || 'N/A';
        const modifiedDate = formatDate(vulnerability.lastModified) || 'N/A';
        const vulnStatus = vulnerability.vulnStatus || 'N/A';

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

        tableBody.appendChild(row);
    });
}

// Function to load CVEs based on the current page and selected results per page
async function loadCVEs(page = 1) {
    currentPage = page;

    const resultsPerPageSelect = document.getElementById('resultsPerPage');
    const resultsPerPage = resultsPerPageSelect.value;

    try {
        const response = await fetch(`/cves/list?resultsPerPage=${resultsPerPage}&page=${page}`);

        if (!response.ok) {
            throw new Error('Failed to fetch CVE data');
        }

        const data = await response.json();
        console.log('Fetched data:', data);

        if (data && data.vulnerabilities) {
            document.getElementById('totalRecords').textContent = `Total Records: ${data.vulnerabilities.length}`;
            displayCVEs(data.vulnerabilities);
            document.getElementById('pageNumber').textContent = `Page ${currentPage}`;

            document.getElementById('prevPage').disabled = currentPage === 1;
            document.getElementById('nextPage').disabled = data.vulnerabilities.length < resultsPerPage;
        } else {
            console.error('No CVE data received');
        }
    } catch (error) {
        console.error('Error fetching CVE data:', error);
    }
}

// Add an event listener for changes to the "resultsPerPage" input
document.getElementById('resultsPerPage').addEventListener('change', () => {
    currentPage = 1; // Reset to the first page when the results per page change
    loadCVEs(currentPage); // Load the first page with the new results per page value
});

// Function to go to the previous page
function prevPage() {
    if (currentPage > 1) {
        loadCVEs(currentPage--);
    }
}

// Function to go to the next page
function nextPage() {
    loadCVEs(currentPage++);
}

// Event listeners for previous and next page buttons
document.getElementById('prevPage').addEventListener('click', prevPage);
document.getElementById('nextPage').addEventListener('click', nextPage);

// Load initial CVEs when the page loads
loadCVEs();
